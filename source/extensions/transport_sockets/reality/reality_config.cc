#include "source/extensions/transport_sockets/reality/reality_config.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ctime>
#include <limits>

#include "envoy/common/exception.h"

#include "source/common/common/fmt.h"
#include "source/common/common/hex.h"
#include "source/common/network/dns_resolver/dns_factory_util.h"

#include "absl/strings/escaping.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

RealityConfig::RealityConfig(
    const envoy::extensions::transport_sockets::reality::v3::RealityConfig& proto, Api::Api& api)
    : api_(api),
      dns_resolver_factory_(Network::createDefaultDnsResolverFactory(dns_resolver_config_)) {
  // REALITY ecosystem encoding: private_key is base64url (Go RawURLEncoding, as
  // printed by `xray x25519` / sing-box), short_id is a hex string. The same
  // strings are reused verbatim by the naive client and sing-box.
  std::string pk;
  if (!absl::WebSafeBase64Unescape(proto.private_key(), &pk) || pk.size() != 32) {
    throw EnvoyException(fmt::format(
        "REALITY private_key must be base64url decoding to 32 bytes, got {}", pk.size()));
  }
  private_key_ = std::vector<uint8_t>(pk.begin(), pk.end());

  short_id_ = Hex::decode(proto.short_id());
  // The short_id gates authentication. An empty short_id previously meant
  // "accept any client", which is an authentication bypass in production.
  // Require a non-empty, at-most-8-byte short_id.
  if (short_id_.empty() || short_id_.size() > 8) {
    throw EnvoyException(fmt::format(
        "REALITY short_id must be a hex string of 1..8 bytes, got {} bytes", short_id_.size()));
  }

  mirror_server_hello_ =
      std::vector<uint8_t>(proto.mirror_server_hello().begin(), proto.mirror_server_hello().end());
  mirror_target_ = proto.mirror_target();
  // At least one mirror source must be configured: a live target to dial, or a
  // static ServerHello to emit (also used as the live-capture fallback).
  if (mirror_server_hello_.empty() && mirror_target_.empty()) {
    throw EnvoyException(
        "REALITY requires at least one of mirror_server_hello or mirror_target");
  }
  // Basic host:port sanity for the live target.
  if (!mirror_target_.empty() && mirror_target_.find(':') == std::string::npos) {
    throw EnvoyException(fmt::format(
        "REALITY mirror_target must be host:port, got '{}'", mirror_target_));
  }

  if (proto.mirror_dial_timeout_seconds() != 0) {
    mirror_dial_timeout_seconds_ = proto.mirror_dial_timeout_seconds();
  }
  if (proto.max_time_diff_seconds() != 0) {
    max_time_diff_seconds_ = proto.max_time_diff_seconds();
  }

  // Optional client version bounds (3 bytes each). PGV enforces len==3 when set,
  // but guard here too so a malformed config fails loudly rather than silently
  // disabling the check.
  if (!proto.min_client_version().empty()) {
    if (proto.min_client_version().size() != 3) {
      throw EnvoyException("REALITY min_client_version must be exactly 3 bytes");
    }
    min_client_version_.assign(proto.min_client_version().begin(),
                               proto.min_client_version().end());
  }
  if (!proto.max_client_version().empty()) {
    if (proto.max_client_version().size() != 3) {
      throw EnvoyException("REALITY max_client_version must be exactly 3 bytes");
    }
    max_client_version_.assign(proto.max_client_version().begin(),
                               proto.max_client_version().end());
  }

  generateEd25519();
}

Network::DnsResolverSharedPtr
RealityConfig::createDnsResolver(Event::Dispatcher& dispatcher) const {
  return THROW_OR_RETURN_VALUE(
      dns_resolver_factory_.createDnsResolver(dispatcher, api_, dns_resolver_config_),
      Network::DnsResolverSharedPtr);
}

std::vector<uint8_t> RealityConfig::makeSelfSignedCert(size_t dummy_ext_len,
                                                       unsigned serial_extra_bytes) const {
  // Minimal self-signed ed25519 certificate (like REALITY Go's init()):
  // serial 0, empty subject == empty issuer.
  bssl::UniquePtr<X509> cert(X509_new());
  if (cert == nullptr) {
    return {};
  }
  X509_set_version(cert.get(), 2); // v3
  // The serial's DER width is the fine-grained size knob: 0 encodes in 3 bytes,
  // 0x0100 in 4, 0x010000 in 5. It absorbs the off-by-one or two that the
  // extension payload alone cannot reach when a length prefix widens.
  long serial = 0;
  for (unsigned i = 0; i < serial_extra_bytes; i++) {
    serial = (serial == 0) ? 0x0100 : serial << 8;
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
  X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), 31536000); // 1 year
  X509_set_pubkey(cert.get(), ed25519_pkey_.get());
  X509_NAME* name = X509_get_subject_name(cert.get());
  X509_set_issuer_name(cert.get(), name);

  if (dummy_ext_len > 0) {
    // Non-critical extension under OID 0.0 (the same arc REALITY's Go
    // implementation uses to reserve room for its ML-DSA-65 signature), holding
    // `dummy_ext_len` zero bytes. Its only purpose is to move the total DER
    // length; nothing reads it.
    bssl::UniquePtr<ASN1_OBJECT> obj(OBJ_txt2obj("0.0", 1 /*dont_search_names*/));
    bssl::UniquePtr<ASN1_OCTET_STRING> value(ASN1_OCTET_STRING_new());
    if (obj == nullptr || value == nullptr) {
      return {};
    }
    const std::vector<uint8_t> zeros(dummy_ext_len, 0);
    if (ASN1_OCTET_STRING_set(value.get(), zeros.data(), static_cast<int>(zeros.size())) != 1) {
      return {};
    }
    bssl::UniquePtr<X509_EXTENSION> ext(
        X509_EXTENSION_create_by_OBJ(nullptr, obj.get(), 0 /*not critical*/, value.get()));
    if (ext == nullptr || X509_add_ext(cert.get(), ext.get(), -1) != 1) {
      return {};
    }
  }

  // Sign with ed25519 (nullptr digest = one-shot, no pre-hash). The 64-byte
  // signature is the DER's trailing 64 bytes, which the handshaker overwrites
  // with HMAC-SHA512(AuthKey, ed25519_pub).
  if (X509_sign(cert.get(), ed25519_pkey_.get(), nullptr) == 0) {
    return {};
  }

  uint8_t* der = nullptr;
  const int der_len = i2d_X509(cert.get(), &der);
  if (der_len <= 0 || der == nullptr) {
    return {};
  }
  std::vector<uint8_t> out(der, der + der_len);
  OPENSSL_free(der);
  return out;
}

std::vector<uint8_t> RealityConfig::buildDisguiseCert(size_t target_der_len) const {
  if (target_der_len <= static_cert_.size() || target_der_len > kMaxDisguiseCertDerLen) {
    return {};
  }

  std::vector<uint8_t> best;
  size_t best_delta = std::numeric_limits<size_t>::max();
  auto consider = [&](std::vector<uint8_t>&& der) {
    if (der.empty()) {
      return;
    }
    const size_t delta = der.size() > target_der_len ? der.size() - target_der_len
                                                     : target_der_len - der.size();
    if (delta < best_delta) {
      best_delta = delta;
      best = std::move(der);
    }
  };

  // Two independent knobs. The extension payload is coarse: the encoded length
  // grows one byte per payload byte, except at the 127/255/65535 length-prefix
  // boundaries where it jumps and leaves a target unreachable. The serial number
  // width is fine and shifts the fixed overhead by 0..2 bytes, filling those
  // gaps. Adding an extension at all costs a fixed overhead, so a small band of
  // targets just above the unpadded size stays unreachable; there the closest
  // encoding is returned.
  for (unsigned serial_extra = 0; serial_extra <= 2 && best_delta != 0; serial_extra++) {
    size_t ext_len = target_der_len > static_cert_.size() + serial_extra
                         ? target_der_len - static_cert_.size() - serial_extra
                         : 1;
    for (int i = 0; i < 8 && best_delta != 0; i++) {
      auto der = makeSelfSignedCert(ext_len, serial_extra);
      if (der.empty()) {
        return {};
      }
      const size_t produced = der.size();
      consider(std::move(der));
      if (produced == target_der_len) {
        break;
      }
      if (produced > target_der_len) {
        const size_t over = produced - target_der_len;
        if (over >= ext_len) {
          break; // cannot shrink further
        }
        ext_len -= over;
      } else {
        ext_len += target_der_len - produced;
      }
    }
    // The iteration can stall a byte or two short when a length prefix widens
    // exactly at the boundary; probe the neighbourhood, and the minimum payload,
    // so the result is the best encoding available.
    for (int64_t candidate : {static_cast<int64_t>(ext_len) - 3,
                              static_cast<int64_t>(ext_len) - 2,
                              static_cast<int64_t>(ext_len) - 1,
                              static_cast<int64_t>(ext_len) + 1,
                              static_cast<int64_t>(ext_len) + 2,
                              static_cast<int64_t>(ext_len) + 3, int64_t{1}}) {
      if (best_delta == 0) {
        break;
      }
      if (candidate <= 0) {
        continue;
      }
      consider(makeSelfSignedCert(static_cast<size_t>(candidate), serial_extra));
    }
  }

  if (best.size() < 64) {
    return {};
  }
  return best;
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

  static_cert_ = makeSelfSignedCert(0, 0);
  if (static_cert_.empty()) {
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
