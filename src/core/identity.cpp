// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/identity.hpp>

#include <cerrno>
#include <utility>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace knetsentry::identity {
namespace {
template<typename T, void (*Free)(T*)>
using Handle = std::unique_ptr<T, decltype(Free)>;
using Certificate = Handle<X509, X509_free>;
using PrivateInfo = Handle<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free>;
struct ErrorQueue {
    ErrorQueue() noexcept { ERR_clear_error(); }
    ~ErrorQueue() { ERR_clear_error(); }
};
struct Fd {
    int value;
    explicit Fd(int fd) noexcept : value(fd) {}
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { if (value >= 0) { (void)::close(value); } }
};
struct Secret {
    std::array<unsigned char, max_key_bytes> bytes{};
    ~Secret() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};
struct Names { const char* key; const char* pending; };
constexpr Names names(Role role) noexcept {
    switch (role) {
    case Role::Agent: return {"agent.key", "agent.key.pending"};
    case Role::Manager: return {"manager.key", "manager.key.pending"};
    case Role::Invalid: break;
    }
    return {nullptr, nullptr};
}
bool private_directory(int fd) noexcept {
    struct stat info{};
    return ::fstat(fd, &info) == 0 && S_ISDIR(info.st_mode) &&
        info.st_uid == ::geteuid() && (info.st_mode & 07777U) == 0700U;
}
bool private_file(int fd, struct stat& info) noexcept {
    return ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_uid == ::geteuid() && (info.st_mode & 07777U) == 0600U &&
        info.st_nlink == 1;
}
bool write_all(int fd, std::span<const unsigned char> bytes) noexcept {
    while (!bytes.empty()) {
        const auto count = ::write(fd, bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { return false; }
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
}
bool read_all(int fd, std::span<unsigned char> bytes) noexcept {
    while (!bytes.empty()) {
        const auto count = ::read(fd, bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR) { continue; }
        if (count <= 0) { return false; }
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    unsigned char extra{};
    ssize_t count{};
    do { count = ::read(fd, &extra, 1); } while (count < 0 && errno == EINTR);
    OPENSSL_cleanse(&extra, sizeof(extra));
    return count == 0;
}
bool valid_key(EVP_PKEY* key) noexcept {
    return key != nullptr && EVP_PKEY_is_a(key, "ED25519") == 1;
}
Certificate parse_certificate(std::span<const unsigned char> der) noexcept {
    if (der.empty() || der.size() > max_certificate_bytes) {
        return Certificate(nullptr, X509_free);
    }
    const auto* cursor = der.data();
    Certificate result(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())), X509_free);
    if (cursor != der.data() + der.size()) { result.reset(); }
    return result;
}
bool leaf_profile(X509* leaf, Role role) noexcept {
    Handle<BASIC_CONSTRAINTS, BASIC_CONSTRAINTS_free> basic(
        static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(leaf, NID_basic_constraints, nullptr, nullptr)),
        BASIC_CONSTRAINTS_free);
    Handle<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free> usage(
        static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(leaf, NID_ext_key_usage, nullptr, nullptr)),
        EXTENDED_KEY_USAGE_free);
    const int purpose = role == Role::Agent ? NID_client_auth : NID_server_auth;
    return basic && basic->ca == 0 && basic->pathlen == nullptr && usage &&
        sk_ASN1_OBJECT_num(usage.get()) == 1 &&
        OBJ_obj2nid(sk_ASN1_OBJECT_value(usage.get(), 0)) == purpose &&
        X509_get_key_usage(leaf) == KU_DIGITAL_SIGNATURE;
}
} // namespace

void KeyDeleter::operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }

KeyResult create_key(int directory, Role role) noexcept {
    ErrorQueue errors;
    const auto file = names(role);
    if (file.key == nullptr) { return {Error::InvalidInput, {}}; }
    if (!private_directory(directory)) { return {Error::UnsafeStorage, {}}; }
    // Refuse overwrite even of an unsafe file/symlink. Publication uses linkat
    // without replacement; a fixed exclusive staging name serializes writers.
    struct stat existing{};
    if (::fstatat(directory, file.key, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        return {Error::AlreadyExists, {}};
    }
    if (errno != ENOENT) { return {Error::Io, {}}; }
    Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    if (!key) { return {Error::Crypto, {}}; }
    PrivateInfo info(EVP_PKEY2PKCS8(key.get()), PKCS8_PRIV_KEY_INFO_free);
    if (!info) { return {Error::Crypto, {}}; }
    Secret secret;
    const int length = i2d_PKCS8_PRIV_KEY_INFO(info.get(), nullptr);
    if (length <= 0 || static_cast<std::size_t>(length) > secret.bytes.size()) {
        return {Error::Crypto, {}};
    }
    auto* cursor = secret.bytes.data();
    if (i2d_PKCS8_PRIV_KEY_INFO(info.get(), &cursor) != length) { return {Error::Crypto, {}}; }
    Fd fd(::openat(directory, file.pending, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (fd.value < 0) { return {errno == EEXIST ? Error::AlreadyExists : Error::Io, {}}; }
    struct stat created{};
    const bool written = ::fchmod(fd.value, 0600) == 0 && private_file(fd.value, created) &&
        write_all(fd.value, std::span(secret.bytes).first(static_cast<std::size_t>(length))) &&
        ::fsync(fd.value) == 0;
    Error outcome = Error::Io;
    if (written) {
        if (::linkat(directory, file.pending, directory, file.key, 0) == 0) {
            outcome = Error::None;
        } else if (errno == EEXIST) { outcome = Error::AlreadyExists; }
    }
    const bool removed = ::unlinkat(directory, file.pending, 0) == 0;
    const bool synced = ::fsync(directory) == 0;
    if (!removed || !synced) {
        outcome = Error::Io;
    }
    if (outcome != Error::None) { return {outcome, {}}; }
    return {Error::None, std::move(key)};
}

KeyResult load_key(int directory, Role role) noexcept {
    ErrorQueue errors;
    const auto file = names(role);
    if (file.key == nullptr) { return {Error::InvalidInput, {}}; }
    if (!private_directory(directory)) { return {Error::UnsafeStorage, {}}; }
    // Nonblocking prevents a malicious FIFO from hanging the service.
    Fd fd(::openat(directory, file.key, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
    if (fd.value < 0) { return {Error::Io, {}}; }
    struct stat info{};
    if (!private_file(fd.value, info)) { return {Error::UnsafeStorage, {}}; }
    if (info.st_size <= 0 || static_cast<unsigned long>(info.st_size) > max_key_bytes) {
        return {Error::InvalidInput, {}};
    }
    Secret secret;
    const auto length = static_cast<std::size_t>(info.st_size);
    if (!read_all(fd.value, std::span(secret.bytes).first(length))) { return {Error::Io, {}}; }
    const auto* cursor = secret.bytes.data();
    PrivateInfo private_info(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &cursor, static_cast<long>(length)),
        PKCS8_PRIV_KEY_INFO_free);
    if (!private_info || cursor != secret.bytes.data() + length) { return {Error::InvalidInput, {}}; }
    Key key(EVP_PKCS82PKEY(private_info.get()));
    if (!valid_key(key.get())) { return {Error::Crypto, {}}; }
    Handle<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr),
        EVP_PKEY_CTX_free);
    if (!context || EVP_PKEY_private_check(context.get()) != 1) { return {Error::Crypto, {}}; }
    return {Error::None, std::move(key)};
}

std::optional<Fingerprint> fingerprint(EVP_PKEY* key) noexcept {
    ErrorQueue errors;
    std::array<unsigned char, 32> public_key{};
    auto size = public_key.size();
    if (!valid_key(key) || EVP_PKEY_get_raw_public_key(key, public_key.data(), &size) != 1 ||
        size != public_key.size()) { return std::nullopt; }
    Fingerprint result{};
    unsigned int digest_size{};
    if (EVP_Digest(public_key.data(), public_key.size(), result.data(), &digest_size,
            EVP_sha256(), nullptr) != 1 || digest_size != result.size()) { return std::nullopt; }
    return result;
}

Error validate_certificate(std::span<const unsigned char> leaf_der,
    std::span<const unsigned char> root_der, Role role, const Fingerprint& expected) noexcept {
    ErrorQueue errors;
    if (names(role).key == nullptr) { return Error::InvalidInput; }
    auto leaf = parse_certificate(leaf_der);
    auto root = parse_certificate(root_der);
    if (!leaf || !root || !leaf_profile(leaf.get(), role)) { return Error::CertificateRejected; }
    Key leaf_key(X509_get_pubkey(leaf.get()));
    Key root_key(X509_get_pubkey(root.get()));
    const auto pin = fingerprint(leaf_key.get());
    if (!pin || CRYPTO_memcmp(pin->data(), expected.data(), expected.size()) != 0 ||
        !valid_key(root_key.get()) || X509_check_ca(root.get()) != 1 ||
        X509_check_issued(root.get(), root.get()) != X509_V_OK ||
        X509_verify(root.get(), root_key.get()) != 1 ||
        EVP_PKEY_eq(leaf_key.get(), root_key.get()) != 0) { return Error::CertificateRejected; }
    Handle<X509_STORE, X509_STORE_free> store(X509_STORE_new(), X509_STORE_free);
    Handle<X509_STORE_CTX, X509_STORE_CTX_free> context(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (!store || !context || X509_STORE_add_cert(store.get(), root.get()) != 1 ||
        X509_STORE_CTX_init(context.get(), store.get(), leaf.get(), nullptr) != 1) { return Error::Crypto; }
    auto* params = X509_STORE_CTX_get0_param(context.get());
    if (params == nullptr || X509_VERIFY_PARAM_set_flags(params,
            X509_V_FLAG_X509_STRICT | X509_V_FLAG_CHECK_SS_SIGNATURE) != 1 ||
        X509_VERIFY_PARAM_set_purpose(params,
            role == Role::Agent ? X509_PURPOSE_SSL_CLIENT : X509_PURPOSE_SSL_SERVER) != 1) {
        return Error::Crypto;
    }
    X509_VERIFY_PARAM_set_depth(params, 0);
    X509_VERIFY_PARAM_set_auth_level(params, 2);
    if (X509_verify_cert(context.get()) != 1 ||
        sk_X509_num(X509_STORE_CTX_get0_chain(context.get())) != 2) { return Error::CertificateRejected; }
    return Error::None;
}
} // namespace knetsentry::identity
