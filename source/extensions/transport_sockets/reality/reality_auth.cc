#include "source/extensions/transport_sockets/reality/reality_auth.h"

#include <openssl/aead.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/mem.h>
#include <openssl/ssl.h>

#include <cstring>
#include <ctime>

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

// This is the single source of truth for the REALITY auth algorithm. It was
// factored out of RealityHandshaker::extractAndVerifyAuth so the same check can
// run in an L4 listener filter (for fallback routing) without a live SSL
// session. See reality_auth.h.
bool realityVerifyAuth(const SSL_CLIENT_HELLO* client_hello,
                       absl::Span<const uint8_t> private_key, absl::Span<const uint8_t> short_id,
                       uint32_t max_time_diff_seconds, RealityAuthResult* out) {
  if (private_key.size() != 32) {
    return false;
  }

  // 1. Find the key_share extension in the ClientHello.
  const uint8_t* ks_ext = nullptr;
  size_t ks_ext_len = 0;
  if (!SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_key_share, &ks_ext,
                                            &ks_ext_len)) {
    return false;
  }

  CBS cbs;
  CBS_init(&cbs, ks_ext, ks_ext_len);
  CBS shares;
  if (!CBS_get_u16_length_prefixed(&cbs, &shares)) {
    return false;
  }

#ifndef SSL_GROUP_X25519_MLKEM768
  constexpr uint16_t kGroupX25519Mlkem768 = 0x11ec;
#else
  constexpr uint16_t kGroupX25519Mlkem768 = SSL_GROUP_X25519_MLKEM768;
#endif
  constexpr size_t kMlkem768PublicKeyBytes = 1184;
  constexpr size_t kHybridKeyShareLen = kMlkem768PublicKeyBytes + 32;

  // peer_pub: client's X25519 public value for the REALITY ECDH (plain X25519
  // share, or the trailing 32 bytes of the hybrid). negotiated_group: the
  // client's FIRST offered supported group (what BoringSSL will negotiate; the
  // mirror must be dialed with it).
  std::vector<uint8_t> peer_pub;
  std::vector<uint8_t> hybrid_x25519;
  uint16_t negotiated_group = 0;
  bool group_chosen = false;
  while (CBS_len(&shares) > 0) {
    uint16_t group;
    CBS key_data;
    if (!CBS_get_u16(&shares, &group) || !CBS_get_u16_length_prefixed(&shares, &key_data)) {
      return false;
    }
    if (group == SSL_CURVE_X25519 && CBS_len(&key_data) == 32) {
      peer_pub.assign(CBS_data(&key_data), CBS_data(&key_data) + 32);
      if (!group_chosen) {
        negotiated_group = SSL_CURVE_X25519;
        group_chosen = true;
      }
    }
    if (group == kGroupX25519Mlkem768 && CBS_len(&key_data) == kHybridKeyShareLen) {
      if (hybrid_x25519.empty()) {
        const uint8_t* x = CBS_data(&key_data) + kMlkem768PublicKeyBytes;
        hybrid_x25519.assign(x, x + 32);
      }
      if (!group_chosen) {
        negotiated_group = kGroupX25519Mlkem768;
        group_chosen = true;
      }
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
  if (X25519(shared_secret.data(), private_key.data(), peer_pub.data()) != 1) {
    return false;
  }

  // 3. HKDF-SHA256: key = HKDF(ikm=shared_secret, salt=random[:20], info="REALITY")
  const uint8_t* random = client_hello->random;
  uint8_t salt[20];
  std::memcpy(salt, random, 20);
  static const uint8_t kInfo[] = {'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
  std::vector<uint8_t> auth_key(32);
  if (HKDF(auth_key.data(), 32, EVP_sha256(), shared_secret.data(), 32, salt, 20, kInfo,
           sizeof(kInfo)) != 1) {
    return false;
  }

  // 4. AES-256-GCM decrypt: nonce=random[20:32], aad=full ClientHello (session_id zeroed).
  if (client_hello->session_id_len != 32) {
    return false;
  }
  std::vector<uint8_t> client_session_id(client_hello->session_id,
                                         client_hello->session_id + client_hello->session_id_len);

  std::vector<uint8_t> aad;
  aad.reserve(4 + client_hello->client_hello_len);
  aad.push_back(0x01); // ClientHello
  uint32_t ch_len = static_cast<uint32_t>(client_hello->client_hello_len);
  aad.push_back((ch_len >> 16) & 0xff);
  aad.push_back((ch_len >> 8) & 0xff);
  aad.push_back(ch_len & 0xff);
  aad.insert(aad.end(), client_hello->client_hello,
             client_hello->client_hello + client_hello->client_hello_len);

  // The client computes the AAD with the session_id field (bytes [39:71]) zeroed.
  if (aad.size() >= 39 + 32) {
    std::memset(aad.data() + 39, 0, 32);
  } else {
    return false;
  }

  std::vector<uint8_t> plaintext(16); // 32 - 16 (tag)
  bssl::UniquePtr<EVP_CIPHER_CTX> ectx(EVP_CIPHER_CTX_new());
  if (!EVP_DecryptInit_ex(ectx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
    return false;
  }
  EVP_CIPHER_CTX_ctrl(ectx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
  EVP_DecryptInit_ex(ectx.get(), nullptr, nullptr, auth_key.data(), random + 20);
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

  // 5a. Anti-replay timestamp check.
  const uint8_t* t = plaintext.data() + 4;
  const uint64_t client_time = (static_cast<uint64_t>(t[0]) << 24) |
                               (static_cast<uint64_t>(t[1]) << 16) |
                               (static_cast<uint64_t>(t[2]) << 8) | static_cast<uint64_t>(t[3]);
  const uint64_t now = static_cast<uint64_t>(::time(nullptr));
  const uint64_t diff = now > client_time ? now - client_time : client_time - now;
  if (diff > max_time_diff_seconds) {
    return false;
  }

  // 5b. Short ID must match exactly.
  const uint8_t* recv_short_id = plaintext.data() + 8;
  if (short_id.empty() || short_id.size() > 8) {
    return false;
  }
  if (CRYPTO_memcmp(recv_short_id, short_id.data(), short_id.size()) != 0) {
    return false;
  }

  if (out != nullptr) {
    out->auth_key = std::move(auth_key);
    out->client_session_id = std::move(client_session_id);
    out->negotiated_group = negotiated_group;
  }
  return true;
}

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
