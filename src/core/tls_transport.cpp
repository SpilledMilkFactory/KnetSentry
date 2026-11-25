// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/tls_transport.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <new>
#include <utility>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace knetsentry::tls {
namespace {
using Clock = std::chrono::steady_clock;
using identity::Role;
constexpr std::array<unsigned char, 9> alpn{8, 'k', 's', 'a', 'p', '/', '1', '.', '0'};
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
Cert parse(std::span<const unsigned char> bytes) noexcept {
    if (bytes.empty() || bytes.size() > identity::max_certificate_bytes) {
        return Cert(nullptr, X509_free);
    }
    const auto* cursor = bytes.data();
    Cert cert(d2i_X509(nullptr, &cursor, static_cast<long>(bytes.size())), X509_free);
    if (cursor != bytes.data() + bytes.size()) { cert.reset(); }
    return cert;
}
int select_alpn(SSL*, const unsigned char** out, unsigned char* out_length,
    const unsigned char* in, unsigned int length, void*) noexcept {
    if (length != alpn.size() || !std::equal(alpn.begin(), alpn.end(), in)) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    *out = alpn.data() + 1;
    *out_length = alpn.front();
    return SSL_TLSEXT_ERR_OK;
}
bool selected_alpn(SSL* ssl) noexcept {
    const unsigned char* selected = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(ssl, &selected, &length);
    return selected != nullptr && length == alpn.size() - 1 &&
        std::equal(alpn.begin() + 1, alpn.end(), selected);
}
} // namespace

struct Session::Impl {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context{nullptr, SSL_CTX_free};
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl{nullptr, SSL_free};
    std::unique_ptr<BIO, decltype(&BIO_free)> wire{nullptr, BIO_free};
    std::array<unsigned char, identity::max_certificate_bytes> root{};
    std::size_t root_size{};
    identity::Fingerprint peer_pin{};
    Role peer_role{Role::Invalid};
    State state{State::Handshake};
    Clock::time_point deadline{Clock::now() + std::chrono::seconds(10)};
    std::size_t handshake_input{};
    std::array<unsigned char, max_plaintext> pending{};
    std::array<unsigned char, max_plaintext> received{};
    std::size_t pending_size{};
    bool peer_verified{};
    bool local_proof_sent{};
    ~Impl() {
        OPENSSL_cleanse(pending.data(), pending.size());
        OPENSSL_cleanse(received.data(), received.size());
    }
    void clear_pending() noexcept {
        OPENSSL_cleanse(pending.data(), pending.size());
        pending_size = 0;
    }
    Status fail() noexcept {
        state = State::Failed;
        clear_pending();
        OPENSSL_cleanse(received.data(), received.size());
        ERR_clear_error();
        return Status::Failed;
    }
    bool expired() noexcept {
        if ((state == State::Handshake || state == State::Closing) && Clock::now() >= deadline) {
            (void)fail();
            return true;
        }
        return false;
    }
    Status classify(int result) noexcept {
        const int error = SSL_get_error(ssl.get(), result);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) { return Status::WouldBlock; }
        return fail();
    }
    void closing() noexcept {
        if (state != State::Closing) { deadline = Clock::now() + std::chrono::seconds(10); }
        state = State::Closing;
    }
    // OpenSSL exposes complete handshake messages to this callback. Require
    // our own CertificateVerify flight: a server that never requests client
    // authentication must not produce a locally Trusted agent session.
    static void observe(int outgoing, int, int type, const void* data,
        std::size_t length, SSL*, void* argument) noexcept {
        auto* self = static_cast<Impl*>(argument);
        if (outgoing == 1 && type == SSL3_RT_HANDSHAKE && data != nullptr && length > 0 &&
            *static_cast<const unsigned char*>(data) == SSL3_MT_CERTIFICATE_VERIFY) {
            self->local_proof_sent = true;
        }
    }
    static int verify(X509_STORE_CTX* ctx, void* argument) noexcept {
        auto* self = static_cast<Impl*>(argument);
        self->peer_verified = false;
        if (X509_verify_cert(ctx) != 1) { return 0; }
        auto* leaf = X509_STORE_CTX_get0_cert(ctx);
        const int length = leaf == nullptr ? 0 : i2d_X509(leaf, nullptr);
        std::array<unsigned char, identity::max_certificate_bytes> bytes{};
        if (length > 0 && static_cast<std::size_t>(length) <= bytes.size()) {
            auto* cursor = bytes.data();
            if (i2d_X509(leaf, &cursor) == length &&
                identity::validate_certificate(std::span(bytes).first(static_cast<std::size_t>(length)),
                    std::span(self->root).first(self->root_size), self->peer_role, self->peer_pin) == identity::Error::None) {
                self->peer_verified = true;
                return 1;
            }
        }
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
};

Session::Session(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Session::~Session() = default;

std::unique_ptr<Session> Session::create(const Credentials& credentials) noexcept {
    ERR_clear_error();
    struct ClearErrors { ~ClearErrors() { ERR_clear_error(); } } clear_errors;
    if (credentials.role != Role::Agent && credentials.role != Role::Manager) { return {}; }
    const auto own_pin = identity::fingerprint(credentials.key);
    if (!own_pin || *own_pin == credentials.peer_pin ||
        identity::validate_certificate(credentials.certificate, credentials.root, credentials.role,
            *own_pin) != identity::Error::None) { return {}; }
    auto leaf = parse(credentials.certificate);
    auto root = parse(credentials.root);
    if (!leaf || !root) { return {}; }
    auto impl = std::unique_ptr<Impl>(new (std::nothrow) Impl);
    if (!impl) { return {}; }
    std::copy(credentials.root.begin(), credentials.root.end(), impl->root.begin());
    impl->root_size = credentials.root.size();
    impl->peer_pin = credentials.peer_pin;
    impl->peer_role = credentials.role == Role::Agent ? Role::Manager : Role::Agent;
    impl->context.reset(SSL_CTX_new(TLS_method()));
    auto* ctx = impl->context.get();
    if (ctx == nullptr || SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256") != 1 ||
        SSL_CTX_set1_groups_list(ctx, "X25519") != 1 || SSL_CTX_set1_sigalgs_list(ctx, "ed25519") != 1 ||
        SSL_CTX_set_num_tickets(ctx, 0) != 1 || SSL_CTX_set_max_early_data(ctx, 0) != 1 ||
        SSL_CTX_set_recv_max_early_data(ctx, 0) != 1 ||
        SSL_CTX_use_certificate(ctx, leaf.get()) != 1 || SSL_CTX_use_PrivateKey(ctx, credentials.key) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1 || X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), root.get()) != 1) {
        return {};
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_post_handshake_auth(ctx, 0);
    SSL_CTX_set_max_cert_list(ctx, 2L * static_cast<long>(identity::max_certificate_bytes));
    SSL_CTX_set_security_level(ctx, 2);
    SSL_CTX_set_verify_depth(ctx, 0);
    auto* params = SSL_CTX_get0_param(ctx);
    if (params == nullptr || X509_VERIFY_PARAM_set_flags(params,
        X509_V_FLAG_X509_STRICT | X509_V_FLAG_CHECK_SS_SIGNATURE) != 1) { return {}; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx, Impl::verify, impl.get());
    SSL_CTX_set_msg_callback(ctx, Impl::observe);
    SSL_CTX_set_msg_callback_arg(ctx, impl.get());
    if (credentials.role == Role::Manager) { SSL_CTX_set_alpn_select_cb(ctx, select_alpn, nullptr); }
    else if (SSL_CTX_set_alpn_protos(ctx, alpn.data(), static_cast<unsigned int>(alpn.size())) != 0) { return {}; }
    impl->ssl.reset(SSL_new(ctx));
    if (!impl->ssl) { return {}; }
    BIO* internal = nullptr;
    BIO* external = nullptr;
    const int paired = BIO_new_bio_pair(&internal, wire_buffer_bytes, &external, wire_buffer_bytes);
    std::unique_ptr<BIO, decltype(&BIO_free)> inner(internal, BIO_free);
    impl->wire.reset(external);
    if (paired != 1) { return {}; }
    auto* endpoint = inner.release();
    SSL_set_bio(impl->ssl.get(), endpoint, endpoint);
    if (credentials.role == Role::Manager) { SSL_set_accept_state(impl->ssl.get()); }
    else { SSL_set_connect_state(impl->ssl.get()); }
    return std::unique_ptr<Session>(new (std::nothrow) Session(std::move(impl)));
}

State Session::state() const noexcept { return impl_->state; }
std::optional<identity::Fingerprint> Session::authenticated_agent() const noexcept {
    if (impl_->state != State::Trusted || impl_->peer_role != Role::Agent || !impl_->peer_verified) { return {}; }
    return impl_->peer_pin;
}
Status Session::handshake() noexcept {
    auto& s = *impl_;
    if (s.expired() || s.state == State::Failed) { return Status::Failed; }
    if (s.state == State::Trusted) { return Status::Ok; }
    if (s.state != State::Handshake) { return Status::NotReady; }
    ERR_clear_error();
    const int result = SSL_do_handshake(s.ssl.get());
    if (result != 1) { return s.classify(result); }
    if (!s.peer_verified || !s.local_proof_sent || SSL_get_verify_result(s.ssl.get()) != X509_V_OK ||
        SSL_version(s.ssl.get()) != TLS1_3_VERSION || SSL_session_reused(s.ssl.get()) != 0 ||
        SSL_get_early_data_status(s.ssl.get()) == SSL_EARLY_DATA_ACCEPTED || !selected_alpn(s.ssl.get())) {
        return s.fail();
    }
    s.state = State::Trusted;
    return Status::Ok;
}
Result Session::ingest(std::span<const unsigned char> bytes) noexcept {
    auto& s = *impl_;
    if (s.expired() || s.state == State::Failed) { return {Status::Failed}; }
    if (s.state == State::Closed) { return {Status::Closed}; }
    if (bytes.empty() || bytes.size() > max_ciphertext_chunk) { return {Status::InvalidInput}; }
    if (s.state == State::Handshake && bytes.size() > max_handshake_input - s.handshake_input) { return {s.fail()}; }
    const int count = BIO_write(s.wire.get(), bytes.data(), static_cast<int>(bytes.size()));
    if (count <= 0) { return {BIO_should_retry(s.wire.get()) ? Status::WouldBlock : s.fail()}; }
    const auto size = static_cast<std::size_t>(count);
    if (s.state == State::Handshake) { s.handshake_input += size; }
    return {Status::Ok, size};
}
Result Session::drain(std::span<unsigned char> bytes) noexcept {
    auto& s = *impl_;
    if (s.expired() || s.state == State::Failed) { return {Status::Failed}; }
    if (bytes.empty() || bytes.size() > max_ciphertext_chunk) { return {Status::InvalidInput}; }
    const int count = BIO_read(s.wire.get(), bytes.data(), static_cast<int>(bytes.size()));
    if (count <= 0) {
        return {s.state == State::Closed ? Status::Closed : (BIO_should_retry(s.wire.get()) ? Status::WouldBlock : s.fail())};
    }
    return {Status::Ok, static_cast<std::size_t>(count)};
}
Result Session::write(std::span<const unsigned char> bytes) noexcept {
    auto& s = *impl_;
    if (s.state == State::Failed) { return {Status::Failed}; }
    if (s.state != State::Trusted) { return {Status::NotReady}; }
    if (bytes.empty() || bytes.size() > max_plaintext) { return {Status::InvalidInput}; }
    if (s.pending_size == 0) {
        std::copy(bytes.begin(), bytes.end(), s.pending.begin());
        s.pending_size = bytes.size();
    } else if (bytes.size() != s.pending_size || !std::equal(bytes.begin(), bytes.end(), s.pending.begin())) {
        return {Status::InvalidInput};
    }
    ERR_clear_error();
    std::size_t count = 0;
    const int result = SSL_write_ex(s.ssl.get(), s.pending.data(), s.pending_size, &count);
    if (result != 1) { return {s.classify(result)}; }
    if (count != s.pending_size) { return {s.fail()}; }
    s.clear_pending();
    return {Status::Ok, count};
}
Result Session::read(std::span<unsigned char, max_plaintext> bytes) noexcept {
    auto& s = *impl_;
    if (s.state == State::Failed) { return {Status::Failed}; }
    if (s.state == State::Closed || s.state == State::Closing) { return {Status::Closed}; }
    if (s.state != State::Trusted) { return {Status::NotReady}; }
    if (s.pending_size != 0) { return {Status::WouldBlock}; }
    ERR_clear_error();
    std::size_t count = 0;
    const int result = SSL_read_ex(s.ssl.get(), s.received.data(), s.received.size(), &count);
    if (result != 1) {
        const int error = SSL_get_error(s.ssl.get(), result);
        OPENSSL_cleanse(s.received.data(), s.received.size());
        if (error == SSL_ERROR_ZERO_RETURN) { s.closing(); return {Status::Closed}; }
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) { return {Status::WouldBlock}; }
        return {s.fail()};
    }
    if (count == 0 || count > s.received.size()) { return {s.fail()}; }
    std::copy_n(s.received.begin(), count, bytes.begin());
    OPENSSL_cleanse(s.received.data(), s.received.size());
    return {Status::Ok, count};
}
Status Session::shutdown() noexcept {
    auto& s = *impl_;
    if (s.expired() || s.state == State::Failed) { return Status::Failed; }
    if (s.state == State::Closed) { return Status::Closed; }
    if (s.state == State::Handshake) { return s.fail(); }
    if (s.pending_size != 0) { return Status::WouldBlock; }
    s.closing();
    ERR_clear_error();
    const int result = SSL_shutdown(s.ssl.get());
    if (result == 1) { s.state = State::Closed; return Status::Closed; }
    if (result == 0) { return Status::WouldBlock; }
    return s.classify(result);
}
void Session::abort() noexcept { if (impl_->state != State::Closed) { (void)impl_->fail(); } }

} // namespace knetsentry::tls
