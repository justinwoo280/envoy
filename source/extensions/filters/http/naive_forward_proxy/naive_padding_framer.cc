#include "source/extensions/filters/http/naive_forward_proxy/naive_padding_framer.h"

#include <algorithm>
#include <cstring>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

size_t PaddingFramer::decode(const uint8_t* data, size_t len, std::string* out_payload) {
  if (decode_state_ == DecodeState::kPassthrough) {
    out_payload->append(reinterpret_cast<const char*>(data), len);
    return len;
  }

  size_t pos = 0;
  while (pos < len) {
    switch (decode_state_) {
    case DecodeState::kPayloadLen1:
      read_payload_len_ = static_cast<uint16_t>(data[pos]) << 8;
      pos++;
      decode_state_ = DecodeState::kPayloadLen2;
      break;

    case DecodeState::kPayloadLen2:
      read_payload_len_ |= data[pos];
      pos++;
      decode_state_ = DecodeState::kPaddingLen;
      break;

    case DecodeState::kPaddingLen:
      read_padding_len_ = data[pos];
      pos++;
      read_payload_buf_.clear();
      if (read_payload_len_ == 0) {
        // Empty payload, skip to padding
        if (read_padding_len_ == 0) {
          num_read_frames_++;
          if (num_read_frames_ >= kFirstPaddings) {
            decode_state_ = DecodeState::kPassthrough;
          } else {
            decode_state_ = DecodeState::kPayloadLen1;
          }
        } else {
          decode_state_ = DecodeState::kPadding;
        }
      } else {
        decode_state_ = DecodeState::kPayload;
      }
      break;

    case DecodeState::kPayload: {
      size_t remaining = len - pos;
      size_t to_copy = std::min(static_cast<size_t>(read_payload_len_) - read_payload_buf_.size(),
                                remaining);
      read_payload_buf_.append(reinterpret_cast<const char*>(data + pos), to_copy);
      pos += to_copy;
      if (read_payload_buf_.size() == read_payload_len_) {
        out_payload->append(read_payload_buf_);
        read_payload_buf_.clear();
        if (read_padding_len_ == 0) {
          num_read_frames_++;
          if (num_read_frames_ >= kFirstPaddings) {
            decode_state_ = DecodeState::kPassthrough;
          } else {
            decode_state_ = DecodeState::kPayloadLen1;
          }
        } else {
          decode_state_ = DecodeState::kPadding;
        }
      }
      break;
    }

    case DecodeState::kPadding: {
      size_t remaining = len - pos;
      size_t to_skip = std::min(static_cast<size_t>(read_padding_len_), remaining);
      pos += to_skip;
      read_padding_len_ -= static_cast<uint8_t>(to_skip);
      if (read_padding_len_ == 0) {
        num_read_frames_++;
        if (num_read_frames_ >= kFirstPaddings) {
          decode_state_ = DecodeState::kPassthrough;
        } else {
          decode_state_ = DecodeState::kPayloadLen1;
        }
      }
      break;
    }

    case DecodeState::kPassthrough:
      out_payload->append(reinterpret_cast<const char*>(data + pos), len - pos);
      pos = len;
      break;
    }
  }
  return pos;
}

std::string PaddingFramer::encode(std::string_view payload, uint8_t padding_size) {
  if (num_written_frames_ >= kFirstPaddings) {
    // Pass-through mode
    return std::string(payload);
  }

  std::string out;
  uint16_t payload_len = static_cast<uint16_t>(payload.size());
  out.reserve(kFrameHeaderSize + payload.size() + padding_size);

  out.push_back(static_cast<char>((payload_len >> 8) & 0xFF));
  out.push_back(static_cast<char>(payload_len & 0xFF));
  out.push_back(static_cast<char>(padding_size));
  out.append(payload);
  out.append(padding_size, '\0');

  num_written_frames_++;
  return out;
}

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
