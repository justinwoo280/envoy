#pragma once

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <vector>

#include "envoy/extensions/transport_sockets/reality/v3/reality.pb.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

struct RealityConfig {
  RealityConfig(const envoy::extensions::transport_sockets::reality::v3::RealityConfig& proto);

  // X25519 private key (raw 32 bytes)
  const std::vector<uint8_t>& privateKey() const { return private_key_; }

  // Short ID (up to 8 bytes)
  const std::vector<uint8_t>& shortId() const { return short_id_; }

  // Mirror ServerHello handshake message bytes (with 4-byte header)
  const std::vector<uint8_t>& mirrorServerHello() const { return mirror_server_hello_; }

  // Maximum allowed |client_time - now| in seconds for anti-replay.
  uint32_t maxTimeDiffSeconds() const { return max_time_diff_seconds_; }

  // Ed25519 private key (EVP_PKEY, for CertificateVerify)
  EVP_PKEY* ed25519PrivateKey() const { return ed25519_pkey_.get(); }

  // Static ed25519 self-signed cert (DER, before HMAC modification)
  const std::vector<uint8_t>& staticCert() const { return static_cert_; }

  // Ed25519 public key (raw 32 bytes, for HMAC computation)
  const std::vector<uint8_t>& ed25519PublicKey() const { return ed25519_pub_; }

private:
  void generateEd25519();

  std::vector<uint8_t> private_key_;       // X25519 raw private key
  std::vector<uint8_t> short_id_;
  std::vector<uint8_t> mirror_server_hello_;
  uint32_t max_time_diff_seconds_{90};

  bssl::UniquePtr<EVP_PKEY> ed25519_pkey_;
  std::vector<uint8_t> ed25519_pub_;       // raw 32 bytes
  std::vector<uint8_t> static_cert_;       // DER
};

using RealityConfigSharedPtr = std::shared_ptr<RealityConfig>;

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
