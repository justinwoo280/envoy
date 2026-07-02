#include "source/extensions/transport_sockets/reality/reality_config.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ctime>

#include "envoy/common/exception.h"

#include "source/common/common/fmt.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

RealityConfig::RealityConfig(
    const envoy::extensions::transport_sockets::reality::v3::RealityConfig& proto) {
  private_key_ = std::vector<uint8_t>(proto.private_key().begin(), proto.private_key().end());
  short_id_ = std::vector<uint8_t>(proto.short_id().begin(), proto.short_id().end());
  mirror_server_hello_ =
      std::vector<uint8_t>(proto.mirror_server_hello().begin(), proto.mirror_server_hello().end());

  // Validate the X25519 private key length. A wrong length would silently
  // produce a garbage shared secret (and thus break auth) or read OOB.
  if (private_key_.size() != 32) {
    throw EnvoyException(fmt::format(
        "REALITY private_key must be exactly 32 bytes, got {}", private_key_.size()));
  }
  // The short_id gates authentication. An empty short_id previously meant
  // "accept any client", which is an authentication bypass in production.
  // Require a non-empty, at-most-8-byte short_id.
  if (short_id_.empty() || short_id_.size() > 8) {
    throw EnvoyException(fmt::format(
        "REALITY short_id must be 1..8 bytes, got {}", short_id_.size()));
  }
  if (mirror_server_hello_.empty()) {
    throw EnvoyException("REALITY mirror_server_hello must be set");
  }

  if (proto.max_time_diff_seconds() != 0) {
    max_time_diff_seconds_ = proto.max_time_diff_seconds();
  }

  generateEd25519();
}

void RealityConfig::generateEd25519() {
  // Generate ed25519 key pair via EVP_PKEY_CTX
  bssl::UniquePtr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
  if (pctx == nullptr || EVP_PKEY_keygen_init(pctx.get()) != 1) {
    throw EnvoyException("REALITY: ed25519 keygen init failed");
  }
  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &pkey) != 1 || pkey == nullptr) {
    throw EnvoyException("REALITY: ed25519 keygen failed");
  }
  ed25519_pkey_.reset(pkey);

  // Extract raw public key (32 bytes)
  size_t pub_len = 32;
  ed25519_pub_.resize(32);
  if (EVP_PKEY_get_raw_public_key(pkey, ed25519_pub_.data(), &pub_len) != 1) {
    throw EnvoyException("REALITY: ed25519 public key extraction failed");
  }
  ed25519_pub_.resize(pub_len);

  // Create a minimal self-signed ed25519 certificate (like REALITY Go's init())
  // Serial = 0, subject/issuer empty, self-signed
  bssl::UniquePtr<X509> cert(X509_new());
  X509_set_version(cert.get(), 2); // v3
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 0);
  X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), 31536000); // 1 year
  X509_set_pubkey(cert.get(), pkey);
  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_set_issuer_name(cert.get(), name);

  // Sign with ed25519 (nullptr digest = one-shot, no pre-hash)
  X509_sign(cert.get(), pkey, nullptr);

  // Convert to DER
  uint8_t* der = nullptr;
  int der_len = i2d_X509(cert.get(), &der);
  if (der_len > 0 && der) {
    static_cert_.assign(der, der + der_len);
    OPENSSL_free(der);
  } else {
    throw EnvoyException("REALITY: failed to serialize ed25519 certificate");
  }
  // The HMAC tail overwrite requires at least 64 trailing bytes (the ed25519
  // signature). Fail fast if the generated cert is unexpectedly short.
  if (static_cert_.size() < 64) {
    throw EnvoyException("REALITY: generated ed25519 certificate too short");
  }
}

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
