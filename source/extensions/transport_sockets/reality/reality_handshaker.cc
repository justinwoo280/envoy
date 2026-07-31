#include "source/extensions/transport_sockets/reality/reality_handshaker.h"

#include "source/extensions/transport_sockets/reality/reality_auth.h"

#include <cstring>

#include <openssl/aes.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>

#include "absl/container/inlined_vector.h"
#include "absl/types/span.h"
#include "openssl/bytestring.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

// ---------------------------------------------------------------------------
// Flight size matching: target DER length for the disguise leaf.
// See the header for the derivation of the 13 and 72 constants.
// ---------------------------------------------------------------------------
namespace {
constexpr size_t kCertificateMsgOverhead = 13;
constexpr size_t kEd25519CertificateVerifyMsgLen = 72;
} // namespace

size_t realityDisguiseCertTargetDerLen(uint32_t mirror_certificate_msg_len,
                                       uint32_t mirror_certificate_verify_msg_len) {
  if (mirror_certificate_msg_len <= kCertificateMsgOverhead ||
      mirror_certificate_verify_msg_len == 0) {
    return 0;
  }
  const size_t flight = static_cast<size_t>(mirror_certificate_msg_len) +
                        static_cast<size_t>(mirror_certificate_verify_msg_len);
  if (flight <= kCertificateMsgOverhead + kEd25519CertificateVerifyMsgLen) {
    return 0;
  }
  return flight - kCertificateMsgOverhead - kEd25519CertificateVerifyMsgLen;
}

// ---------------------------------------------------------------------------
// ex_data index for retrieving RealityHandshaker* from SSL*
// ---------------------------------------------------------------------------
static int g_reality_ex_data_index = []() {
  return SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
}();

int RealityHandshaker::exDataIndex() { return g_reality_ex_data_index; }

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------
RealityHandshaker::RealityHandshaker(bssl::UniquePtr<SSL> ssl,
                                     int ssl_extended_socket_info_index,
                                     Ssl::HandshakeCallbacks* handshake_callbacks,
                                     RealityConfigSharedPtr config)
    : SslHandshakerImpl(std::move(ssl), ssl_extended_socket_info_index, handshake_callbacks),
      config_(std::move(config)) {
  // Store `this` in SSL ex_data so the static callbacks can find us
  SSL_set_ex_data(ssl_.get(), exDataIndex(), this);
}

RealityHandshaker::~RealityHandshaker() {
  // Wipe the derived HKDF AuthKey; it is key material and should not linger in
  // freed heap memory (defense against memory disclosure).
  if (!auth_key_.empty()) {
    OPENSSL_cleanse(auth_key_.data(), auth_key_.size());
  }
}

// ---------------------------------------------------------------------------
// doHandshake — delegates to parent (SslHandshakerImpl), which calls
// SSL_do_handshake. The select_certificate_cb fires inside SSL_do_handshake
// and handles the REALITY flow. No override logic needed here beyond
// delegation — the REALITY magic happens in the callbacks.
// ---------------------------------------------------------------------------
Network::PostIoAction RealityHandshaker::doHandshake() {
  return SslHandshakerImpl::doHandshake();
}

// ---------------------------------------------------------------------------
// Static select_certificate_cb — dispatches to the per-SSL RealityHandshaker
// ---------------------------------------------------------------------------
ssl_select_cert_result_t RealityHandshaker::selectCertCb_(const SSL_CLIENT_HELLO* client_hello) {
  auto* handshaker = static_cast<RealityHandshaker*>(
      SSL_get_ex_data(client_hello->ssl, exDataIndex()));
  if (handshaker == nullptr) {
    return ssl_select_cert_error;
  }
  return handshaker->onSelectCertificate(client_hello);
}

// ---------------------------------------------------------------------------
// Static reality_serverhello_cb — dispatches to the per-SSL RealityHandshaker
// ---------------------------------------------------------------------------
bool RealityHandshaker::realityServerHelloCb_(SSL* ssl, const uint8_t** out, size_t* out_len) {
  auto* handshaker = static_cast<RealityHandshaker*>(SSL_get_ex_data(ssl, exDataIndex()));
  if (handshaker == nullptr) {
    return false;
  }
  return handshaker->onRealityServerHello(out, out_len);
}

// ---------------------------------------------------------------------------
// onRealityServerHello — return the mirror ServerHello bytes to emit.
//
// Prefers a live-captured ServerHello (mirror_sh_, filled by
// onMirrorDialComplete in live mode). Falls back to the static
// mirror_server_hello from config (static mode, or when the live dial failed).
// ---------------------------------------------------------------------------
bool RealityHandshaker::onRealityServerHello(const uint8_t** out, size_t* out_len) {
  if (mirror_sh_.empty()) {
    // No live capture available: use the static fallback.
    const auto& sh = config_->mirrorServerHello();
    if (sh.empty()) {
      return false;
    }
    mirror_sh_ = sh;
  }
  // ServerHello layout: header(4) + legacy_version(2) + random(32) +
  // session_id_len(1) at offset 38, then session_id. TLS 1.3 requires the
  // ServerHello's legacy_session_id_echo to equal the ClientHello's
  // legacy_session_id; the captured mirror still holds the original target's
  // session_id, so overwrite it with this client's (must both be 32 bytes).
  if (client_session_id_.size() == 32 && mirror_sh_.size() >= 39 + 32 &&
      mirror_sh_[38] == 32) {
    std::memcpy(mirror_sh_.data() + 39, client_session_id_.data(), 32);
  }
  *out = mirror_sh_.data();
  *out_len = mirror_sh_.size();
  return true;
}

// ---------------------------------------------------------------------------
// onSelectCertificate — REALITY auth + cert injection
// ---------------------------------------------------------------------------
ssl_select_cert_result_t RealityHandshaker::onSelectCertificate(
    const SSL_CLIENT_HELLO* client_hello) {
  if (state_ == State::AuthDone) {
    // Resumed call: auth and (in live mode) the mirror dial are done, so the
    // target's flight sizes are known. Inject the certificate now — deferring it
    // to this point is what lets the disguise leaf be padded to match.
    if (!cert_injected_) {
      if (!injectTempCert() || !injectPrivateKey()) {
        ENVOY_LOG(error, "REALITY cert/key injection failed");
        return ssl_select_cert_error;
      }
      cert_injected_ = true;
    }
    return ssl_select_cert_success;
  }
  if (state_ == State::MirrorPending) {
    // The live mirror dial is still in flight; keep the handshake suspended.
    return ssl_select_cert_retry;
  }

  // First call: extract REALITY auth
  if (!extractAndVerifyAuth(client_hello)) {
    ENVOY_LOG(debug, "REALITY auth failed");
    return ssl_select_cert_error;
  }

  // Live mirror: suspend the handshake, dial the real target asynchronously to
  // capture its ServerHello and measure its encrypted flight, then resume. If
  // the dial cannot be started, fall through to static mode.
  if (config_->hasLiveMirror() && startLiveMirrorDial()) {
    state_ = State::MirrorPending;
    return ssl_select_cert_retry;
  }

  // Static mode (or live dial could not start): proceed immediately with the
  // unpadded certificate. The reality_serverhello_cb will use the static
  // mirror_server_hello.
  state_ = State::AuthDone;
  if (!injectTempCert() || !injectPrivateKey()) {
    ENVOY_LOG(error, "REALITY cert/key injection failed");
    return ssl_select_cert_error;
  }
  cert_injected_ = true;
  return ssl_select_cert_success;
}

Network::DnsResolver& RealityHandshaker::dnsResolver() {
  if (dns_resolver_ == nullptr) {
    // Build a per-worker resolver on this connection's dispatcher. A c-ares
    // resolver must be created and driven on the same thread that resolves.
    dns_resolver_ = config_->createDnsResolver(handshakeCallbacks()->connection().dispatcher());
  }
  return *dns_resolver_;
}

bool RealityHandshaker::startLiveMirrorDial() {
  auto* cb = handshakeCallbacks();
  if (cb == nullptr) {
    return false;
  }
  Event::Dispatcher& dispatcher = cb->connection().dispatcher();

  // Parse "host:port" from the configured target.
  const std::string& target = config_->mirrorTarget();
  const auto colon = target.rfind(':');
  if (colon == std::string::npos) {
    return false;
  }
  std::string host = target.substr(0, colon);
  uint32_t port = 0;
  try {
    port = static_cast<uint32_t>(std::stoul(target.substr(colon + 1)));
  } catch (...) {
    return false;
  }
  if (host.empty() || port == 0 || port > 65535) {
    return false;
  }

  // Ensure the per-worker resolver exists, then hand its shared_ptr to the
  // dialer (keeps it alive for the dial's lifetime).
  dnsResolver();
  const auto timeout = std::chrono::seconds(config_->mirrorDialTimeoutSeconds());
  mirror_dialer_ = std::make_unique<MirrorDialer>(
      dispatcher, dns_resolver_, std::move(host), port, negotiated_group_,
      std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
      [this](MirrorCapture&& capture) { onMirrorDialComplete(std::move(capture)); });
  mirror_dialer_->start();
  return true;
}

void RealityHandshaker::onMirrorDialComplete(MirrorCapture&& capture) {
  if (!capture.server_hello.empty()) {
    // Adopt the live-captured ServerHello; onRealityServerHello will fix up the
    // session_id and the patch replaces the key_share.
    mirror_capture_ = std::move(capture);
    mirror_sh_ = mirror_capture_.server_hello;
    if (mirror_capture_.flight_complete) {
      ENVOY_LOG(debug,
                "REALITY live mirror captured: ServerHello {} bytes, flight EE={} Cert={} CV={} "
                "Fin={}",
                mirror_sh_.size(), mirror_capture_.encrypted_extensions_len,
                mirror_capture_.certificate_len, mirror_capture_.certificate_verify_len,
                mirror_capture_.finished_len);
    } else {
      ENVOY_LOG(debug,
                "REALITY live mirror captured: ServerHello {} bytes, flight not measured "
                "(certificate size will not be matched)",
                mirror_sh_.size());
    }
  } else {
    // Live capture failed: leave mirror_sh_ empty so onRealityServerHello falls
    // back to the static config (if present).
    mirror_capture_ = MirrorCapture{};
    ENVOY_LOG(debug, "REALITY live mirror failed; falling back to static ServerHello");
  }
  state_ = State::AuthDone;
  // The dialer calls us from inside one of its own methods, so destroying it here
  // would tear down the frame we were called from. Hand it to the dispatcher and
  // let it die on the next iteration.
  if (mirror_dialer_ != nullptr) {
    std::shared_ptr<MirrorDialer> dying(std::move(mirror_dialer_));
    handshakeCallbacks()->connection().dispatcher().post([dying]() {});
  }
  // Resume the suspended client-facing handshake.
  handshakeCallbacks()->onAsynchronousCertificateSelectionComplete();
}

// ---------------------------------------------------------------------------
// extractAndVerifyAuth — X25519 + HKDF + AES-GCM, compatible with REALITY Go
// ---------------------------------------------------------------------------
bool RealityHandshaker::extractAndVerifyAuth(const SSL_CLIENT_HELLO* client_hello) {
  // Delegate to the shared, session-less auth function (single source of truth,
  // also used by the L4 fallback listener filter). Copy the derived values this
  // handshaker needs (HKDF key, client session_id to echo, negotiated group for
  // the mirror dial) out of the result.
  RealityAuthResult result;
  if (!realityVerifyAuth(client_hello, absl::MakeConstSpan(config_->privateKey()),
                         absl::MakeConstSpan(config_->shortId()), config_->maxTimeDiffSeconds(),
                         absl::MakeConstSpan(config_->minClientVersion()),
                         absl::MakeConstSpan(config_->maxClientVersion()), &result)) {
    return false;
  }
  auth_key_ = std::move(result.auth_key);
  client_session_id_ = std::move(result.client_session_id);
  negotiated_group_ = result.negotiated_group;
  ENVOY_LOG(debug, "REALITY auth verified");
  return true;
}

// ---------------------------------------------------------------------------
// injectTempCert — create temp-trusted cert (ed25519 + HMAC tail)
//
// When the mirror dial measured the target's encrypted flight, the leaf is
// padded so that our EncryptedExtensions..Finished flight is the same size as
// the target's. Without this, an observer of an authenticated session sees a
// ServerHello that matches the real site byte-for-byte followed by a ~350-byte
// certificate flight where the real site serves several kilobytes — a
// single-connection, zero-false-positive discriminator.
// ---------------------------------------------------------------------------
bool RealityHandshaker::injectTempCert() {
  temp_cert_.clear();

  if (mirror_capture_.flight_complete) {
    const size_t target = realityDisguiseCertTargetDerLen(
        mirror_capture_.certificate_len, mirror_capture_.certificate_verify_len);
    if (target != 0) {
      temp_cert_ = config_->buildDisguiseCert(target);
      if (temp_cert_.empty()) {
        ENVOY_LOG(debug,
                  "REALITY: cannot size disguise leaf to {} bytes (mirror Cert={} CV={}); using "
                  "unpadded certificate",
                  target, mirror_capture_.certificate_len,
                  mirror_capture_.certificate_verify_len);
      } else {
        const size_t emitted_flight = temp_cert_.size() + kCertificateMsgOverhead +
                                      kEd25519CertificateVerifyMsgLen;
        const size_t mirror_flight = static_cast<size_t>(mirror_capture_.certificate_len) +
                                     static_cast<size_t>(mirror_capture_.certificate_verify_len);
        ENVOY_LOG(debug,
                  "REALITY: disguise leaf padded to {} bytes; Certificate+CertificateVerify {} vs "
                  "mirror {}{}",
                  temp_cert_.size(), emitted_flight, mirror_flight,
                  mirror_capture_.saw_certificate_request
                      ? " (mirror also sent CertificateRequest; not reproduced)"
                      : "");
      }
    }
  }

  if (temp_cert_.empty()) {
    temp_cert_ = config_->staticCert();
  }

  // Compute HMAC-SHA512(AuthKey, ed25519_public_key) → 64 bytes
  uint8_t hmac_out[64];
  unsigned int hmac_len = 64;
  if (HMAC(EVP_sha512(), auth_key_.data(), auth_key_.size(),
           config_->ed25519PublicKey().data(), config_->ed25519PublicKey().size(), hmac_out,
           &hmac_len) == nullptr ||
      hmac_len != 64) {
    ENVOY_LOG(error, "REALITY HMAC computation failed");
    return false;
  }

  // Overwrite last 64 bytes of the cert with the HMAC. X.509 puts signatureValue
  // last, so this replaces the Ed25519 self-signature regardless of any padding
  // extension. Config guarantees the cert is >= 64 bytes, but re-check
  // defensively (untrusted-ish invariant).
  if (temp_cert_.size() < 64) {
    ENVOY_LOG(error, "REALITY static cert too short for HMAC overwrite");
    return false;
  }
  memcpy(temp_cert_.data() + temp_cert_.size() - 64, hmac_out, 64);

  // Inject via SSL_use_certificate_ASN1
  if (SSL_use_certificate_ASN1(ssl_.get(), temp_cert_.data(), temp_cert_.size()) != 1) {
    ENVOY_LOG(error, "REALITY SSL_use_certificate_ASN1 failed");
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// injectPrivateKey — set ed25519 private key on SSL for CertificateVerify
// ---------------------------------------------------------------------------
bool RealityHandshaker::injectPrivateKey() {
  if (SSL_use_PrivateKey(ssl_.get(), config_->ed25519PrivateKey()) != 1) {
    ENVOY_LOG(error, "REALITY SSL_use_PrivateKey failed");
    return false;
  }
  // The injected leaf is an Ed25519 cert, so the server's CertificateVerify
  // must be signed with Ed25519. Because the handshaker declares
  // provides_sigalgs=true, BoringSSL does NOT auto-configure the server signing
  // prefs; without this the handshake fails with NO_COMMON_SIGNATURE_ALGORITHMS
  // right after REALITY auth succeeds.
  static const uint16_t kEd25519[] = {SSL_SIGN_ED25519};
  if (SSL_set_signing_algorithm_prefs(ssl_.get(), kEd25519, 1) != 1) {
    ENVOY_LOG(error, "REALITY SSL_set_signing_algorithm_prefs failed");
    return false;
  }
  return true;
}

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
