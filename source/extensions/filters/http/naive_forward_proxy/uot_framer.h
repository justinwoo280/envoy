#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

// Magic address for UoT v2 (sing-box compatible).
inline constexpr const char* kUotMagicAddress = "sp.v2.udp-over-tcp.arpa";
inline constexpr const char* kUotLegacyMagicAddress = "sp.udp-over-tcp.arpa";

// SOCKS5 address type constants (used for the UoT handshake address, matching
// sing-box M.SocksaddrSerializer).
inline constexpr uint8_t kAtypIPv4 = 0x01;
inline constexpr uint8_t kAtypIPv6 = 0x04;
inline constexpr uint8_t kAtypDomain = 0x03;

// UoT per-frame address type constants (sing-box uot.AddrParser). These
// deliberately differ from the SOCKS5 constants above and are used for the
// per-packet destination in isConnect=false data frames.
inline constexpr uint8_t kUotAtypIPv4 = 0x00;
inline constexpr uint8_t kUotAtypIPv6 = 0x01;
inline constexpr uint8_t kUotAtypDomain = 0x02;

// Selects which address-type byte mapping to use.
enum class AddrScheme { Socks5, Uot };

// A parsed host:port pair extracted from UoT handshake or per-frame address.
struct HostPort {
  std::string host;
  uint16_t port = 0;
};

// Encodes an address (ATYP + addr + port) into a byte string using the given
// scheme (SOCKS5 for the handshake, UoT for per-frame addresses).
std::string encodeAddress(const HostPort& hp, AddrScheme scheme);

// Backwards-compatible alias: encodes using the SOCKS5 scheme.
inline std::string encodeSocks5Address(const HostPort& hp) {
  return encodeAddress(hp, AddrScheme::Socks5);
}

// Decodes an address from a byte buffer using the given scheme.
// Returns the parsed HostPort and the number of bytes consumed.
// Returns nullopt on invalid OR incomplete data. When it returns nullopt,
// *fatal (if provided) distinguishes the two: true = the address-type byte is
// invalid (unrecoverable — caller must abort), false = need more bytes.
// This lets the stateful decoder avoid getting stuck forever on a malformed
// per-frame address (a DoS/hang vector with untrusted input).
struct Socks5AddressParseResult {
  HostPort hp;
  size_t consumed;
};
std::optional<Socks5AddressParseResult> decodeAddress(const uint8_t* data, size_t len,
                                                      AddrScheme scheme, bool* fatal = nullptr);
inline std::optional<Socks5AddressParseResult> decodeSocks5Address(const uint8_t* data,
                                                                   size_t len) {
  return decodeAddress(data, len, AddrScheme::Socks5);
}

// UoT v2 wire format:
//
// Handshake (first frame):
//   [1 byte: isConnect (0 or 1)]
//   [SOCKS5 address: ATYP + addr + port]
//
// Data frames (isConnect=true):
//   [2 bytes BE: payload_length] [payload]
//
// Data frames (isConnect=false):
//   [SOCKS5 address: ATYP + addr + port] [2 bytes BE: payload_length] [payload]
//
// Server→Client direction:
//   Server sends a handshake echo first, then data frames.
//   For isConnect=true: data frames are [len(2)][payload]
//   For isConnect=false: data frames are [SOCKS5 addr][len(2)][payload]
//   (address = source of the UDP datagram)

// ---- Encode side (server → client) ----

// Encodes a UoT handshake frame for the server→client direction.
// isConnect should match the client's handshake.
std::string encodeHandshake(bool is_connect, const HostPort& dest);

// Encodes a UoT data frame (isConnect=true mode).
// Returns [2 bytes BE length][payload].
std::string encodeDataFrame(uint16_t length, std::string_view payload);

// Encodes a UoT data frame (isConnect=false mode).
// Returns [SOCKS5 addr][2 bytes BE length][payload].
std::string encodeDataFrameWithAddr(const HostPort& src, uint16_t length,
                                    std::string_view payload);

// ---- Decode side (client → server) ----

enum class FrameType { kHandshake, kData, kError };

struct UotFrame {
  FrameType type = FrameType::kError;
  bool is_connect = false;
  HostPort destination;
  std::string payload;
};

// Stateful UoT frame decoder. Handles TCP byte-stream fragmentation.
class UotDecoder {
public:
  UotDecoder();

  // Feeds bytes into the decoder. Returns a frame if a complete frame was
  // decoded. *consumed is set to the number of bytes consumed from the input.
  // When a frame is complete, consumed may be less than len (remaining bytes
  // belong to the next frame and must be fed again).
  // Returns nullopt if no complete frame yet (need more bytes or error).
  std::optional<UotFrame> feed(const uint8_t* data, size_t len, size_t* consumed);

  bool handshakeDone() const { return handshake_done_; }
  bool isConnect() const { return is_connect_; }
  bool hasError() const { return has_error_; }

private:
  enum class State {
    kHandshakeIsConnect,
    kHandshakeAddr,
    kHandshakeAddrData,
    kHandshakePort,
    kDataLen1,
    kDataLen2,
    kDataAddr,    // isConnect=false: per-frame address (decoded in one step)
    kDataPayload,
  };

  void setState(State s);

  State state_ = State::kHandshakeIsConnect;
  bool handshake_done_ = false;
  bool is_connect_ = false;
  bool has_error_ = false;

  // Address parsing state (reused for handshake and per-frame addresses).
  uint8_t addr_type_ = 0;
  std::vector<uint8_t> addr_buf_;
  size_t addr_needed_ = 0;
  std::string domain_buf_;
  size_t domain_needed_ = 0;
  uint16_t port_ = 0;

  // Data frame state.
  uint16_t data_length_ = 0;
  std::string payload_;

  // Accumulated address for current frame (isConnect=false data frames).
  HostPort frame_dest_;
};

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
