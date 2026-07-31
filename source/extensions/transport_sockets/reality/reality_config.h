#pragma once

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <string>
#include <vector>

#include "envoy/api/api.h"
#include "envoy/config/core/v3/extension.pb.h"
#include "envoy/event/dispatcher.h"
#include "envoy/extensions/transport_sockets/reality/v3/reality.pb.h"
#include "envoy/network/dns.h"
#include "envoy/network/dns_resolver.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

struct RealityConfig {
  RealityConfig(const envoy::extensions::transport_sockets::reality::v3::RealityConfig& proto,
                Api::Api& api);

  // X25519 private key (raw 32 bytes)
  const std::vector<uint8_t>& privateKey() const { return private_key_; }

  // Short ID (up to 8 bytes)
  const std::vector<uint8_t>& shortId() const { return short_id_; }

  // Static fallback mirror ServerHello handshake message bytes (with 4-byte
  // header). May be empty when a live mirror_target is configured.
  const std::vector<uint8_t>& mirrorServerHello() const { return mirror_server_hello_; }

  // Live mirror target ("host:port"), empty if not configured (static mode).
  const std::string& mirrorTarget() const { return mirror_target_; }

  // Whether a live mirror target is configured.
  bool hasLiveMirror() const { return !mirror_target_.empty(); }

  // Timeout for the live mirror dial + capture.
  uint32_t mirrorDialTimeoutSeconds() const { return mirror_dial_timeout_seconds_; }

  // Create a DNS resolver bound to the given (worker-thread) dispatcher. The
  // resolver MUST live on and be driven by the same thread that resolves; a
  // c-ares resolver's fd/epoll state is not thread-safe. Mirrors the pattern in
  // the naive_forward_proxy filter.
  Network::DnsResolverSharedPtr createDnsResolver(Event::Dispatcher& dispatcher) const;

  // Maximum allowed |client_time - now| in seconds for anti-replay.
  uint32_t maxTimeDiffSeconds() const { return max_time_diff_seconds_; }

  // Minimum / maximum accepted client version (3 bytes each, or empty = no
  // bound). Compared big-endian against the decrypted session_id version tuple.
  const std::vector<uint8_t>& minClientVersion() const { return min_client_version_; }
  const std::vector<uint8_t>& maxClientVersion() const { return max_client_version_; }

  // Ed25519 private key (EVP_PKEY, for CertificateVerify)
  EVP_PKEY* ed25519PrivateKey() const { return ed25519_pkey_.get(); }

  // Static ed25519 self-signed cert (DER, before HMAC modification)
  const std::vector<uint8_t>& staticCert() const { return static_cert_; }

  // Build a self-signed Ed25519 disguise leaf whose DER encoding is
  // `target_der_len` bytes long, by sizing a non-critical dummy extension. Used
  // to make the emitted certificate flight the same size as the mirror target's,
  // which mirroring the ServerHello alone does not achieve.
  //
  // The signature stays the last 64 bytes of the DER (X.509 puts signatureValue
  // last), so the caller's HMAC tail overwrite is unaffected.
  //
  // DER length prefixes widen at 127/255/65535 boundaries. Two knobs (the dummy
  // extension payload and the serial number's width) cover almost every target
  // exactly; a handful of lengths where the outer prefixes widen together are
  // reachable only to within one byte, and a small band just above the unpadded
  // size is not reachable at all because adding an extension has a fixed cost. In
  // those cases the closest achievable encoding is returned.
  //
  // Returns an empty vector if `target_der_len` is at or below the unpadded cert
  // size or above `kMaxDisguiseCertDerLen`, in which case the caller must fall
  // back to staticCert().
  std::vector<uint8_t> buildDisguiseCert(size_t target_der_len) const;

  // Upper bound on a padded disguise leaf. Generous enough for post-quantum
  // certificate chains (ML-DSA-65 leaves alone run to several kilobytes) while
  // still bounding the memory a single connection can be made to allocate.
  static constexpr size_t kMaxDisguiseCertDerLen = 32768;

  // Ed25519 public key (raw 32 bytes, for HMAC computation)
  const std::vector<uint8_t>& ed25519PublicKey() const { return ed25519_pub_; }

private:
  void generateEd25519();
  // Build and self-sign the disguise leaf. `dummy_ext_len == 0` emits no
  // extension at all, reproducing the minimal certificate byte-for-byte.
  // `serial_extra_bytes` (0..2) widens the serial number's DER encoding, the
  // fine-grained knob used to reach lengths the extension payload alone skips.
  // Returns an empty vector on failure.
  std::vector<uint8_t> makeSelfSignedCert(size_t dummy_ext_len,
                                          unsigned serial_extra_bytes) const;

  std::vector<uint8_t> private_key_;       // X25519 raw private key
  std::vector<uint8_t> short_id_;
  std::vector<uint8_t> mirror_server_hello_;
  std::string mirror_target_;              // "host:port", empty = static mode
  uint32_t mirror_dial_timeout_seconds_{5};
  uint32_t max_time_diff_seconds_{90};
  std::vector<uint8_t> min_client_version_; // empty = no lower bound
  std::vector<uint8_t> max_client_version_; // empty = no upper bound

  bssl::UniquePtr<EVP_PKEY> ed25519_pkey_;
  std::vector<uint8_t> ed25519_pub_;       // raw 32 bytes
  std::vector<uint8_t> static_cert_;       // DER

  // DNS resolution for the live mirror target. Declared before the factory
  // because the factory is initialized from the config.
  Api::Api& api_;
  envoy::config::core::v3::TypedExtensionConfig dns_resolver_config_;
  Network::DnsResolverFactory& dns_resolver_factory_;
};

using RealityConfigSharedPtr = std::shared_ptr<RealityConfig>;

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
