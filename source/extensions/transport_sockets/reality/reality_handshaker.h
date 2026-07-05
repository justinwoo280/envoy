#pragma once

#include <openssl/ssl.h>

#include <vector>

#include "envoy/network/dns.h"

#include "source/common/tls/ssl_handshaker.h"
#include "source/extensions/transport_sockets/reality/mirror_dialer.h"
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

  // Kick off the async live mirror dial (live mode). Returns true if the dial
  // was started (handshake should suspend), false if it could not start (caller
  // falls back to the static ServerHello and proceeds synchronously).
  bool startLiveMirrorDial();
  // Completion callback for the mirror dial (fires on the connection's
  // dispatcher). Stores the captured ServerHello (or leaves mirror_sh_ empty for
  // static fallback) and resumes the suspended handshake.
  void onMirrorDialComplete(std::vector<uint8_t>&& server_hello);
  // Lazily create a per-worker DNS resolver bound to this connection's
  // dispatcher (a c-ares resolver must run on the thread that resolves).
  Network::DnsResolver& dnsResolver();

  RealityConfigSharedPtr config_;

  enum class State { Initial, MirrorPending, AuthDone };
  State state_{State::Initial};

  // Computed per-connection
  std::vector<uint8_t> auth_key_;       // 32 bytes, derived HKDF key
  std::vector<uint8_t> temp_cert_;      // modified cert DER
  std::vector<uint8_t> client_session_id_; // client's ClientHello session_id (echo in SH)
  std::vector<uint8_t> mirror_sh_;      // per-conn mirror ServerHello with session_id echoed
  uint16_t negotiated_group_{0};        // group the client offered (for dialing the mirror)

  // Live mirror dial state.
  MirrorDialerPtr mirror_dialer_;
  Network::DnsResolverSharedPtr dns_resolver_;
};

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
