#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

// NaiveProxy Variant1 padding framer.
//
// Wire format (Variant1, first kFirstPaddings=8 frames):
//   [len_hi][len_lo][pad_size][payload][pad_size bytes of zeros]
//
// After 8 frames, padding is disabled and data passes through raw.
//
// The framer is stateful: it tracks the number of frames read/written
// and automatically switches to pass-through mode after 8 frames.

inline constexpr int kFirstPaddings = 8;
inline constexpr int kFrameHeaderSize = 3; // [len_hi][len_lo][pad_size]
inline constexpr int kMaxPaddingSize = 255;

class PaddingFramer {
public:
  PaddingFramer() = default;

  // ---- Decode side (strip padding) ----

  // Feeds padded data into the decoder. Extracted payload is appended to
  // *out_payload. Returns the number of bytes consumed from input.
  // After kFirstPaddings frames, switches to pass-through mode.
  size_t decode(const uint8_t* data, size_t len, std::string* out_payload);

  // ---- Encode side (add padding) ----

  // Encodes payload with padding. padding_size is the number of zero bytes
  // to append. Returns the padded frame.
  // After kFirstPaddings frames, returns payload without padding.
  std::string encode(std::string_view payload, uint8_t padding_size);

  // ---- State ----

  int framesRead() const { return num_read_frames_; }
  int framesWritten() const { return num_written_frames_; }
  bool decodePaddingActive() const { return num_read_frames_ < kFirstPaddings; }
  bool encodePaddingActive() const { return num_written_frames_ < kFirstPaddings; }

private:
  enum class DecodeState {
    kPayloadLen1,
    kPayloadLen2,
    kPaddingLen,
    kPayload,
    kPadding,
    kPassthrough,
  };

  DecodeState decode_state_ = DecodeState::kPayloadLen1;
  int num_read_frames_ = 0;
  int num_written_frames_ = 0;

  uint16_t read_payload_len_ = 0;
  uint8_t read_padding_len_ = 0;
  std::string read_payload_buf_;
};

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
