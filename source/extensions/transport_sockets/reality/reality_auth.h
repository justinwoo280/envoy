#pragma once

#include <openssl/ssl.h>

#include <cstdint>
#include <vector>

#include "absl/types/span.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

// Derived values produced by a successful REALITY authentication. The transport
// socket handshaker needs these to drive the mirror + ECDH; the L4 listener
// filter (fallback routing) only needs the boolean verdict and can ignore them.
struct RealityAuthResult {
  std::vector<uint8_t> auth_key;          // 32-byte HKDF-derived key
  std::vector<uint8_t> client_session_id; // client's legacy_session_id (echo in SH)
  uint16_t negotiated_group{0};           // client's first-offered supported group
};

// Verify REALITY authentication over a parsed ClientHello. This is the single
// source of truth for the auth algorithm (X25519 -> HKDF-SHA256 -> AES-256-GCM
// over the session_id, plus timestamp anti-replay and short_id match). It is a
// pure function of the ClientHello and the configured key material — it does not
// touch any live SSL session state — so it can be reused both inside the
// transport socket's select_certificate_cb and in an L4 listener filter that
// parses the ClientHello from raw peeked bytes (buffer-only SSL_CTX).
//
// `min_client_version` and `max_client_version`, when non-empty, must each be
// exactly 3 bytes; the decrypted client version (session_id plaintext[0:3]) is
// compared big-endian (most-significant byte first) and rejected if outside the
// inclusive [min, max] range. Empty means that bound is not enforced. Mirrors
// REALITY's MinClientVer / MaxClientVer.
//
// Returns true and fills `out` (if non-null) on success; returns false on any
// failure (parse error, bad tag, stale timestamp, short_id mismatch, or version
// out of range).
bool realityVerifyAuth(const SSL_CLIENT_HELLO* client_hello,
                       absl::Span<const uint8_t> private_key, absl::Span<const uint8_t> short_id,
                       uint32_t max_time_diff_seconds,
                       absl::Span<const uint8_t> min_client_version,
                       absl::Span<const uint8_t> max_client_version, RealityAuthResult* out);

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
