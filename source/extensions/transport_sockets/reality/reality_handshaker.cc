#include "source/extensions/transport_sockets/reality/reality_handshaker.h"

#include <openssl/aes.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>

#include "absl/container/inlined_vector.h"
#include "openssl/bytestring.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

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
// onRealityServerHello — return the pre-configured mirror ServerHello bytes
// ---------------------------------------------------------------------------
bool RealityHandshaker::onRealityServerHello(const uint8_t** out, size_t* out_len) {
  const auto& sh = config_->mirrorServerHello();
  if (sh.empty()) {
    return false;
  }
  *out = sh.data();
  *out_len = sh.size();
  return true;
}

// ---------------------------------------------------------------------------
// onSelectCertificate — REALITY auth + cert injection
// ---------------------------------------------------------------------------
ssl_select_cert_result_t RealityHandshaker::onSelectCertificate(
    const SSL_CLIENT_HELLO* client_hello) {
  if (state_ == State::AuthDone) {
    // Second call: auth already done, proceed with handshake
    return ssl_select_cert_success;
  }

  // First call: extract REALITY auth
  if (!extractAndVerifyAuth(client_hello)) {
    ENVOY_LOG(debug, "REALITY auth failed");
    return ssl_select_cert_error;
  }

  // Auth OK — inject temp-trusted cert and private key
  if (!injectTempCert() || !injectPrivateKey()) {
    ENVOY_LOG(error, "REALITY cert/key injection failed");
    return ssl_select_cert_error;
  }

  state_ = State::AuthDone;
  return ssl_select_cert_success;
}

// ---------------------------------------------------------------------------
// extractAndVerifyAuth — X25519 + HKDF + AES-GCM, compatible with REALITY Go
// ---------------------------------------------------------------------------
bool RealityHandshaker::extractAndVerifyAuth(const SSL_CLIENT_HELLO* client_hello) {
  // 1. Find X25519 key share in ClientHello extensions
  const uint8_t* ks_ext = nullptr;
  size_t ks_ext_len = 0;
  if (!SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_key_share, &ks_ext,
                                             &ks_ext_len)) {
    return false;
  }

  // Parse key_share extension: client_shares_len(2) + [group(2) + key_len(2) + key(key_len)]...
  CBS cbs;
  CBS_init(&cbs, ks_ext, ks_ext_len);
  CBS shares;
  if (!CBS_get_u16_length_prefixed(&cbs, &shares)) {
    return false;
  }

  // REALITY authenticates using the client's X25519 public value. The client
  // may offer it either as a plain X25519 key share (32 bytes) or as the
  // X25519 component of the post-quantum hybrid X25519MLKEM768 key share, whose
  // wire layout is [ MLKEM768_public_key (1184) ][ X25519_public_key (32) ].
  // This matches the client-side patch and REALITY's own behavior of using
  // keyShare.data[EncapsulationKeySize768:] for the hybrid group. We collect
  // both candidates in one pass and prefer plain X25519 if present.
  //
  // Constants (from BoringSSL): SSL_GROUP_X25519_MLKEM768 = 0x11ec,
  // MLKEM768_PUBLIC_KEY_BYTES = 1184. Named constants are used if available.
#ifndef SSL_GROUP_X25519_MLKEM768
  constexpr uint16_t kGroupX25519Mlkem768 = 0x11ec;
#else
  constexpr uint16_t kGroupX25519Mlkem768 = SSL_GROUP_X25519_MLKEM768;
#endif
  constexpr size_t kMlkem768PublicKeyBytes = 1184;
  constexpr size_t kHybridKeyShareLen = kMlkem768PublicKeyBytes + 32;

  std::vector<uint8_t> peer_pub;        // chosen X25519 public key (32 bytes)
  std::vector<uint8_t> hybrid_x25519;   // fallback from X25519MLKEM768
  while (CBS_len(&shares) > 0) {
    uint16_t group, key_len;
    CBS key_data;
    if (!CBS_get_u16(&shares, &group) || !CBS_get_u16_length_prefixed(&shares, &key_data)) {
      return false;
    }
    (void)key_len;
    if (group == SSL_CURVE_X25519 && CBS_len(&key_data) == 32) {
      peer_pub.assign(CBS_data(&key_data), CBS_data(&key_data) + 32);
      break; // plain X25519 preferred; stop searching
    }
    if (group == kGroupX25519Mlkem768 && CBS_len(&key_data) == kHybridKeyShareLen &&
        hybrid_x25519.empty()) {
      // X25519 public value is the trailing 32 bytes.
      const uint8_t* x = CBS_data(&key_data) + kMlkem768PublicKeyBytes;
      hybrid_x25519.assign(x, x + 32);
      // keep scanning in case a plain X25519 share also appears
    }
  }
  if (peer_pub.empty() && !hybrid_x25519.empty()) {
    peer_pub = std::move(hybrid_x25519);
  }
  if (peer_pub.empty()) {
    return false;
  }

  // 2. X25519 ECDH: AuthKey = X25519(server_priv, client_pub)
  std::vector<uint8_t> shared_secret(32);
  if (X25519(shared_secret.data(), config_->privateKey().data(), peer_pub.data()) != 1) {
    return false;
  }

  // 3. HKDF-SHA256: key = HKDF(ikm=shared_secret, salt=random[:20], info="REALITY")
  const uint8_t* random = client_hello->random;
  uint8_t salt[20];
  memcpy(salt, random, 20);
  static const uint8_t kInfo[] = {'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
  auth_key_.resize(32);
  if (HKDF(auth_key_.data(), 32, EVP_sha256(), shared_secret.data(), 32, salt, 20, kInfo,
           sizeof(kInfo)) != 1) {
    return false;
  }

  // 4. AES-256-GCM decrypt: nonce=random[20:32], aad=full ClientHello (with header)
  //    ciphertext = session_id (32 bytes = 16 plaintext + 16 tag)
  if (client_hello->session_id_len != 32) {
    return false;
  }

  // AAD = handshake header (type=0x01 + 3-byte length) + client_hello body
  std::vector<uint8_t> aad;
  aad.reserve(4 + client_hello->client_hello_len);
  aad.push_back(0x01); // ClientHello
  uint32_t ch_len = static_cast<uint32_t>(client_hello->client_hello_len);
  aad.push_back((ch_len >> 16) & 0xff);
  aad.push_back((ch_len >> 8) & 0xff);
  aad.push_back(ch_len & 0xff);
  aad.insert(aad.end(), client_hello->client_hello, client_hello->client_hello + client_hello->client_hello_len);

  // CRITICAL: the client computes the AEAD AAD over the ClientHello with the
  // session_id field (bytes [39:71] of the handshake message: 4-byte header +
  // 2-byte legacy_version + 32-byte random + 1-byte session_id_len brings us to
  // offset 39) ZEROED. We must zero the same bytes here or the GCM tag will
  // never verify. Without this, every REALITY handshake fails authentication.
  if (aad.size() >= 39 + 32) {
    memset(aad.data() + 39, 0, 32);
  } else {
    return false;
  }

  std::vector<uint8_t> plaintext(16); // 32 - 16 (tag) = 16
  // Use EVP for AES-256-GCM
  bssl::UniquePtr<EVP_CIPHER_CTX> ectx(EVP_CIPHER_CTX_new());
  if (!EVP_DecryptInit_ex(ectx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
    return false;
  }
  EVP_CIPHER_CTX_ctrl(ectx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
  EVP_DecryptInit_ex(ectx.get(), nullptr, nullptr, auth_key_.data(), random + 20);
  int len;
  EVP_DecryptUpdate(ectx.get(), nullptr, &len, aad.data(), aad.size());
  EVP_DecryptUpdate(ectx.get(), plaintext.data(), &len, client_hello->session_id, 16);
  if (EVP_CIPHER_CTX_ctrl(ectx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                           const_cast<uint8_t*>(client_hello->session_id + 16)) != 1) {
    return false;
  }
  int flen;
  if (EVP_DecryptFinal_ex(ectx.get(), nullptr, &flen) != 1) {
    return false; // GCM tag verification failed
  }

  // 5. Verify plaintext: ver[0:3] + reserved[3] + time[4:8 BE] + shortId[8:16].
  if (plaintext.size() < 16) {
    return false;
  }

  // 5a. Anti-replay: reject if the embedded timestamp is too far from now.
  //     Mirrors REALITY's MaxTimeDiff check.
  const uint8_t* t = plaintext.data() + 4;
  const uint64_t client_time = (static_cast<uint64_t>(t[0]) << 24) |
                               (static_cast<uint64_t>(t[1]) << 16) |
                               (static_cast<uint64_t>(t[2]) << 8) |
                               static_cast<uint64_t>(t[3]);
  const uint64_t now = static_cast<uint64_t>(::time(nullptr));
  const uint64_t diff = now > client_time ? now - client_time : client_time - now;
  if (diff > config_->maxTimeDiffSeconds()) {
    ENVOY_LOG(debug, "REALITY timestamp out of range: diff={}s max={}s", diff,
              config_->maxTimeDiffSeconds());
    return false;
  }

  // 5b. Short ID must match exactly. The config layer already guarantees a
  //     non-empty, <=8-byte short_id (no "accept any" bypass).
  const uint8_t* recv_short_id = plaintext.data() + 8;
  const auto& cfg_short_id = config_->shortId();
  if (cfg_short_id.empty() || cfg_short_id.size() > 8) {
    return false;
  }
  if (CRYPTO_memcmp(recv_short_id, cfg_short_id.data(), cfg_short_id.size()) != 0) {
    ENVOY_LOG(debug, "REALITY short_id mismatch");
    return false;
  }

  ENVOY_LOG(debug, "REALITY auth verified");
  return true;
}

// ---------------------------------------------------------------------------
// injectTempCert — create temp-trusted cert (ed25519 + HMAC tail)
// ---------------------------------------------------------------------------
bool RealityHandshaker::injectTempCert() {
  // Copy the static cert
  temp_cert_ = config_->staticCert();

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

  // Overwrite last 64 bytes of the cert with the HMAC. Config guarantees the
  // cert is >= 64 bytes, but re-check defensively (untrusted-ish invariant).
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
