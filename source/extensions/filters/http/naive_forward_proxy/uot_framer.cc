#include "source/extensions/filters/http/naive_forward_proxy/uot_framer.h"

#include <algorithm>
#include <cstring>

#include "source/common/common/byte_order.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

namespace {

uint16_t readBE16(const uint8_t* p) {
  return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

void writeBE16(uint8_t* p, uint16_t v) {
  p[0] = (v >> 8) & 0xFF;
  p[1] = v & 0xFF;
}

} // namespace

namespace {

struct SchemeBytes {
  uint8_t v4;
  uint8_t v6;
  uint8_t domain;
};

SchemeBytes schemeBytes(AddrScheme scheme) {
  if (scheme == AddrScheme::Uot) {
    return {kUotAtypIPv4, kUotAtypIPv6, kUotAtypDomain};
  }
  return {kAtypIPv4, kAtypIPv6, kAtypDomain};
}

} // namespace

std::string encodeAddress(const HostPort& hp, AddrScheme scheme) {
  const SchemeBytes b = schemeBytes(scheme);
  std::string out;
  // Try to parse as IPv4.
  uint8_t ip4[4];
  if (sscanf(hp.host.c_str(), "%hhu.%hhu.%hhu.%hhu", &ip4[0], &ip4[1], &ip4[2], &ip4[3]) == 4) {
    out.push_back(static_cast<char>(b.v4));
    out.append(reinterpret_cast<const char*>(ip4), 4);
  } else {
    // IPv6 literals are carried as domains here (matches the existing decoder,
    // which reconstructs a colon-hex string). A future improvement is to encode
    // real 16-byte IPv6. Domain length is clamped to 255.
    std::string host = hp.host;
    if (host.size() > 255) {
      host.resize(255);
    }
    out.push_back(static_cast<char>(b.domain));
    out.push_back(static_cast<char>(host.size()));
    out.append(host);
  }
  uint8_t port_be[2];
  writeBE16(port_be, hp.port);
  out.append(reinterpret_cast<const char*>(port_be), 2);
  return out;
}

std::optional<Socks5AddressParseResult> decodeAddress(const uint8_t* data, size_t len,
                                                      AddrScheme scheme, bool* fatal) {
  if (fatal != nullptr) {
    *fatal = false;
  }
  const SchemeBytes b = schemeBytes(scheme);
  if (len < 1) return std::nullopt;
  uint8_t atyp = data[0];
  size_t off = 1;

  HostPort hp;
  if (atyp == b.v4) {
    if (len < off + 6) return std::nullopt;
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", data[off], data[off + 1], data[off + 2],
             data[off + 3]);
    hp.host = buf;
    hp.port = readBE16(data + off + 4);
    off += 6;
  } else if (atyp == b.v6) {
    if (len < off + 18) return std::nullopt;
    char buf[64];
    const uint8_t* p = data + off;
    snprintf(buf, sizeof(buf),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", p[0], p[1],
             p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14],
             p[15]);
    hp.host = buf;
    hp.port = readBE16(data + off + 16);
    off += 18;
  } else if (atyp == b.domain) {
    if (len < off + 1) return std::nullopt;
    uint8_t dlen = data[off++];
    if (dlen == 0) return std::nullopt; // empty host is invalid
    if (len < off + dlen + 2) return std::nullopt;
    hp.host = std::string(reinterpret_cast<const char*>(data + off), dlen);
    hp.port = readBE16(data + off + dlen);
    off += dlen + 2;
  } else {
    // Unknown address-type byte: unrecoverable, not a "need more bytes" case.
    if (fatal != nullptr) {
      *fatal = true;
    }
    return std::nullopt;
  }

  return Socks5AddressParseResult{hp, off};
}

std::string encodeHandshake(bool is_connect, const HostPort& dest) {
  std::string out;
  out.push_back(is_connect ? 0x01 : 0x00);
  out += encodeAddress(dest, AddrScheme::Socks5);
  return out;
}

std::string encodeDataFrame(uint16_t length, std::string_view payload) {
  std::string out;
  uint8_t len_be[2];
  writeBE16(len_be, length);
  out.append(reinterpret_cast<const char*>(len_be), 2);
  out.append(payload);
  return out;
}

std::string encodeDataFrameWithAddr(const HostPort& src, uint16_t length,
                                    std::string_view payload) {
  // Per-frame addresses use the UoT scheme (0x00/0x01/0x02), not SOCKS5.
  std::string out = encodeAddress(src, AddrScheme::Uot);
  uint8_t len_be[2];
  writeBE16(len_be, length);
  out.append(reinterpret_cast<const char*>(len_be), 2);
  out.append(payload);
  return out;
}

// ---- UotDecoder ----

UotDecoder::UotDecoder() = default;

void UotDecoder::setState(State s) {
  state_ = s;
  addr_buf_.clear();
  addr_needed_ = 0;
  domain_buf_.clear();
  domain_needed_ = 0;
}

std::optional<UotFrame> UotDecoder::feed(const uint8_t* data, size_t len, size_t* consumed) {
  if (has_error_) {
    if (consumed) *consumed = 0;
    return std::nullopt;
  }

  size_t pos = 0;
  while (pos < len) {
    size_t remaining = len - pos;

    switch (state_) {
    case State::kHandshakeIsConnect: {
      is_connect_ = (data[pos] != 0);
      pos++;
      setState(State::kHandshakeAddr);
      break;
    }

    case State::kHandshakeAddr: {
      addr_type_ = data[pos];
      pos++;
      if (addr_type_ == kAtypIPv4) {
        // NOTE: setState() clears addr_needed_, so it MUST be set AFTER.
        setState(State::kHandshakeAddrData);
        addr_needed_ = 4;
      } else if (addr_type_ == kAtypIPv6) {
        setState(State::kHandshakeAddrData);
        addr_needed_ = 16;
      } else if (addr_type_ == kAtypDomain) {
        setState(State::kHandshakeAddrData);
        // Next byte is domain length, handled in kHandshakeAddrData
        domain_needed_ = 0; // 0 means we need to read the length byte
      } else {
        has_error_ = true;
        if (consumed) *consumed = pos;
        return std::nullopt;
      }
      break;
    }

    case State::kHandshakeAddrData: {
      if (addr_type_ == kAtypDomain && domain_needed_ == 0) {
        // Read domain length
        domain_needed_ = data[pos];
        pos++;
        if (domain_needed_ == 0) {
          // Empty domain is an invalid destination; reject (matches the
          // per-frame decodeAddress behavior and avoids a bogus "" host).
          has_error_ = true;
          if (consumed) *consumed = pos;
          return std::nullopt;
        }
        break;
      }
      // Accumulate address bytes.
      if (addr_type_ == kAtypDomain) {
        size_t to_copy = std::min(domain_needed_ - domain_buf_.size(), remaining);
        domain_buf_.append(reinterpret_cast<const char*>(data + pos), to_copy);
        pos += to_copy;
        if (domain_buf_.size() == domain_needed_) {
          frame_dest_.host = domain_buf_;
          setState(State::kHandshakePort);
        }
      } else {
        size_t to_copy = std::min(addr_needed_ - addr_buf_.size(), remaining);
        addr_buf_.insert(addr_buf_.end(), data + pos, data + pos + to_copy);
        pos += to_copy;
        if (addr_buf_.size() == addr_needed_) {
          if (addr_type_ == kAtypIPv4) {
            char b[16];
            snprintf(b, sizeof(b), "%d.%d.%d.%d", addr_buf_[0], addr_buf_[1],
                     addr_buf_[2], addr_buf_[3]);
            frame_dest_.host = b;
          } else {
            // IPv6
            char b[64];
            const uint8_t* p = addr_buf_.data();
            snprintf(b, sizeof(b),
                     "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                     p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                     p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15]);
            frame_dest_.host = b;
          }
          setState(State::kHandshakePort);
        }
      }
      break;
    }

    case State::kHandshakePort: {
      size_t to_copy = std::min(size_t{2} - addr_buf_.size(), remaining);
      addr_buf_.insert(addr_buf_.end(), data + pos, data + pos + to_copy);
      pos += to_copy;
      if (addr_buf_.size() == 2) {
        frame_dest_.port = readBE16(addr_buf_.data());
        handshake_done_ = true;

        UotFrame frame;
        frame.type = FrameType::kHandshake;
        frame.is_connect = is_connect_;
        frame.destination = frame_dest_;

        if (is_connect_) {
          setState(State::kDataLen1);
        } else {
          setState(State::kDataAddr);
        }
        if (consumed) *consumed = pos;
        return frame;
      }
      break;
    }

    case State::kDataAddr: {
      // isConnect=false: per-frame address starts here, using the UoT scheme
      // (0x00/0x01/0x02), which differs from the handshake's SOCKS5 scheme.
      bool fatal = false;
      auto result = decodeAddress(data + pos, remaining, AddrScheme::Uot, &fatal);
      if (!result) {
        if (fatal) {
          // Invalid address-type byte: unrecoverable. Without this, a single
          // bad byte would wedge the decoder forever (consumed stays 0), a
          // silent hang / resource-leak DoS with untrusted input.
          has_error_ = true;
          if (consumed) *consumed = pos;
          return std::nullopt;
        }
        // Incomplete: wait for more bytes.
        if (consumed) *consumed = pos;
        return std::nullopt;
      }
      frame_dest_ = result->hp;
      pos += result->consumed;
      setState(State::kDataLen1);
      break;
    }

    case State::kDataLen1: {
      data_length_ = static_cast<uint16_t>(data[pos]) << 8;
      pos++;
      setState(State::kDataLen2);
      break;
    }

    case State::kDataLen2: {
      data_length_ |= data[pos];
      pos++;
      payload_.clear();
      if (data_length_ == 0) {
        // Empty payload
        UotFrame frame;
        frame.type = FrameType::kData;
        frame.is_connect = is_connect_;
        frame.destination = frame_dest_;
        setState(is_connect_ ? State::kDataLen1 : State::kDataAddr);
        if (consumed) *consumed = pos;
        return frame;
      }
      setState(State::kDataPayload);
      break;
    }

    case State::kDataPayload: {
      size_t to_copy = std::min(static_cast<size_t>(data_length_) - payload_.size(), remaining);
      payload_.append(reinterpret_cast<const char*>(data + pos), to_copy);
      pos += to_copy;
      if (payload_.size() == data_length_) {
        UotFrame frame;
        frame.type = FrameType::kData;
        frame.is_connect = is_connect_;
        frame.destination = frame_dest_;
        frame.payload = std::move(payload_);
        payload_.clear();
        setState(is_connect_ ? State::kDataLen1 : State::kDataAddr);
        if (consumed) *consumed = pos;
        return frame;
      }
      break;
    }
    }
  }

  if (consumed) *consumed = pos;
  return std::nullopt;
}

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
