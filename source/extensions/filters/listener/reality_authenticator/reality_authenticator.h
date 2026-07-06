#pragma once

#include <cstdint>
#include <vector>

#include "envoy/extensions/filters/listener/reality_authenticator/v3/reality_authenticator.pb.h"
#include "envoy/network/filter.h"

#include "source/common/common/logger.h"

#include "openssl/ssl.h"
#include "openssl/ssl3.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace RealityAuthenticator {

// Dynamic metadata this filter writes: namespace key + boolean field.
extern const char kMetadataNamespace[];
extern const char kAuthenticatedField[];

// Shared config: parsed key material + a buffer-only SSL_CTX to parse the
// ClientHello from raw peeked bytes (same technique as tls_inspector).
class Config {
public:
  Config(const envoy::extensions::filters::listener::reality_authenticator::v3::RealityAuthenticator&
             proto_config);

  bssl::UniquePtr<SSL> newSsl();
  const std::vector<uint8_t>& privateKey() const { return private_key_; }
  const std::vector<uint8_t>& shortId() const { return short_id_; }
  uint32_t maxTimeDiffSeconds() const { return max_time_diff_seconds_; }

  // Max ClientHello BoringSSL will accept.
  static constexpr size_t TLS_MAX_CLIENT_HELLO = SSL3_RT_MAX_PLAIN_LENGTH;

private:
  bssl::UniquePtr<SSL_CTX> ssl_ctx_;
  std::vector<uint8_t> private_key_;
  std::vector<uint8_t> short_id_;
  uint32_t max_time_diff_seconds_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

// L4 REALITY authenticator listener filter. Peeks the ClientHello (never
// consumes it), runs REALITY auth, and writes {authenticated: bool} into dynamic
// metadata for a filter_chain_matcher to route on. Always returns Continue so
// the connection proceeds to filter-chain selection either way.
class Filter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Filter(const ConfigSharedPtr& config);

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;
  Network::FilterStatus onData(Network::ListenerFilterBuffer& buffer) override;
  size_t maxReadBytes() const override { return requested_read_bytes_; }

private:
  enum class ParseState { Done, Continue, Error };
  ParseState parseClientHello(const void* data, size_t len);
  void setAuthenticated(bool authenticated);

  ConfigSharedPtr config_;
  Network::ListenerFilterCallbacks* cb_{};
  bssl::UniquePtr<SSL> ssl_;
  uint64_t read_{0};
  uint32_t requested_read_bytes_;
  bool verdict_written_{false};

  friend class Config;
};

} // namespace RealityAuthenticator
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
