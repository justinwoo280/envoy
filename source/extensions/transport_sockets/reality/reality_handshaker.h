#pragma once

#include <openssl/ssl.h>

#include <vector>

#include "source/common/tls/ssl_handshaker.h"
#include "source/extensions/transport_sockets/reality/reality_config.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

class RealityHandshaker : public Tls::SslHandshakerImpl {
public:
  RealityHandshaker(bssl::UniquePtr<SSL> ssl, int ssl_extended_socket_info_index,
                    Ssl::HandshakeCallbacks* handshake_callbacks,
                    RealityConfigSharedPtr config);
  ~RealityHandshaker() override;

  // Ssl::Handshaker
  Network::PostIoAction doHandshake() override;

  // SSL ex_data index for RealityHandshaker*
  static int exDataIndex();

  // Static callbacks (set on SSL_CTX / globally by sslctxCb)
  static ssl_select_cert_result_t selectCertCb_(const SSL_CLIENT_HELLO* client_hello);
  static bool realityServerHelloCb_(SSL* ssl, const uint8_t** out, size_t* out_len);

private:
  // Called from the static select_certificate_cb
  ssl_select_cert_result_t onSelectCertificate(const SSL_CLIENT_HELLO* client_hello);

  // Called from the static reality_serverhello_cb
  bool onRealityServerHello(const uint8_t** out, size_t* out_len);
  // REALITY auth extraction: X25519 + HKDF + AES-GCM
  // Returns true if auth is valid, false otherwise
  bool extractAndVerifyAuth(const SSL_CLIENT_HELLO* client_hello);

  // Inject temp-trusted cert (ed25519 + HMAC tail) via SSL_use_certificate_ASN1.
  // Returns false on failure.
  bool injectTempCert();

  // Set ed25519 private key on the SSL for CertificateVerify. Returns false on
  // failure.
  bool injectPrivateKey();

  RealityConfigSharedPtr config_;

  enum class State { Initial, AuthDone };
  State state_{State::Initial};

  // Computed per-connection
  std::vector<uint8_t> auth_key_;       // 32 bytes, derived HKDF key
  std::vector<uint8_t> temp_cert_;      // modified cert DER
  std::vector<uint8_t> client_session_id_; // client's ClientHello session_id (echo in SH)
  std::vector<uint8_t> mirror_sh_;      // per-conn mirror ServerHello with session_id echoed
};

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
