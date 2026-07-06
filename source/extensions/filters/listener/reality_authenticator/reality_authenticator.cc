#include "source/extensions/filters/listener/reality_authenticator/reality_authenticator.h"

#include <algorithm>

#include "envoy/buffer/buffer.h"
#include "envoy/common/exception.h"
#include "envoy/network/listen_socket.h"

#include "source/common/common/assert.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/router/string_accessor_impl.h"
#include "source/extensions/transport_sockets/reality/reality_auth.h"

#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace RealityAuthenticator {

const char kMetadataNamespace[] = "envoy.filters.listener.reality_authenticator";
const char kAuthenticatedField[] = "authenticated";
const char kFilterStateKey[] = "envoy.filters.listener.reality_authenticator.authenticated";

namespace {
// Per-SSL slot to reach the Filter from the select_certificate_cb.
int realitySslFilterIndex() {
  static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return idx;
}
} // namespace

Config::Config(
    const envoy::extensions::filters::listener::reality_authenticator::v3::RealityAuthenticator&
        proto_config)
    : ssl_ctx_(SSL_CTX_new(TLS_with_buffers_method())) {
  std::string pk;
  if (!absl::Base64Unescape(proto_config.private_key(), &pk) || pk.size() != 32) {
    throw EnvoyException("reality_authenticator: private_key must be base64 of 32 bytes");
  }
  private_key_.assign(pk.begin(), pk.end());

  std::string sid;
  if (!absl::Base64Unescape(proto_config.short_id(), &sid) || sid.empty() || sid.size() > 8) {
    throw EnvoyException("reality_authenticator: short_id must be base64 of 1..8 bytes");
  }
  short_id_.assign(sid.begin(), sid.end());

  max_time_diff_seconds_ =
      proto_config.max_time_diff_seconds() == 0 ? 90 : proto_config.max_time_diff_seconds();

  SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS1_3_VERSION);
  SSL_CTX_set_options(ssl_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(ssl_ctx_.get(), SSL_SESS_CACHE_OFF);
  SSL_CTX_set_select_certificate_cb(
      ssl_ctx_.get(), [](const SSL_CLIENT_HELLO* client_hello) -> ssl_select_cert_result_t {
        Filter* filter =
            static_cast<Filter*>(SSL_get_ex_data(client_hello->ssl, realitySslFilterIndex()));
        const Config& cfg = *filter->config_;
        const bool ok = TransportSockets::Reality::realityVerifyAuth(
            client_hello, absl::MakeConstSpan(cfg.privateKey()),
            absl::MakeConstSpan(cfg.shortId()), cfg.maxTimeDiffSeconds(), /*out=*/nullptr);
        filter->setAuthenticated(ok);
        // Always abort: we only parse+authenticate, never terminate TLS here.
        return ssl_select_cert_error;
      });
}

bssl::UniquePtr<SSL> Config::newSsl() { return bssl::UniquePtr<SSL>{SSL_new(ssl_ctx_.get())}; }

Filter::Filter(const ConfigSharedPtr& config)
    : config_(config), ssl_(config_->newSsl()),
      requested_read_bytes_(Config::TLS_MAX_CLIENT_HELLO) {
  SSL_set_ex_data(ssl_.get(), realitySslFilterIndex(), this);
  SSL_set_accept_state(ssl_.get());
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  cb_ = &cb;
  return Network::FilterStatus::StopIteration;
}

void Filter::setAuthenticated(bool authenticated) {
  // Write the verdict as a string FilterState object so a filter_chain_matcher
  // using FilterStateInput (which reads serializeAsString()) + exact_match_map
  // can route on "true"/"false". Dynamic metadata (bool) is also written for
  // observability/logging.
  cb_->filterState().setData(
      kFilterStateKey, std::make_shared<Router::StringAccessorImpl>(authenticated ? "true" : "false"),
      StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection);

  Protobuf::Struct metadata;
  auto& fields = *metadata.mutable_fields();
  fields[kAuthenticatedField].set_bool_value(authenticated);
  cb_->setDynamicMetadata(kMetadataNamespace, metadata);

  verdict_written_ = true;
  ENVOY_LOG(debug, "reality_authenticator: authenticated={}", authenticated);
}

Network::FilterStatus Filter::onData(Network::ListenerFilterBuffer& buffer) {
  const Buffer::ConstRawSlice raw_slice = buffer.rawSlice();
  if (static_cast<uint64_t>(raw_slice.len_) > read_) {
    const uint8_t* data = static_cast<const uint8_t*>(raw_slice.mem_) + read_;
    const size_t len = raw_slice.len_ - read_;
    read_ = raw_slice.len_;
    switch (parseClientHello(data, len)) {
    case ParseState::Error:
      // Could not parse a ClientHello (plaintext / malformed): treat as
      // unauthenticated so it falls back to the real dest, then continue.
      if (!verdict_written_) {
        setAuthenticated(false);
      }
      return Network::FilterStatus::Continue;
    case ParseState::Done:
      return Network::FilterStatus::Continue;
    case ParseState::Continue:
      return Network::FilterStatus::StopIteration;
    }
  }
  return Network::FilterStatus::StopIteration;
}

Filter::ParseState Filter::parseClientHello(const void* data, size_t len) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data, len));
  BIO_set_mem_eof_return(bio.get(), -1);
  SSL_set0_rbio(ssl_.get(), bssl::UpRef(bio).release());

  int ret = SSL_do_handshake(ssl_.get());
  // The select_certificate_cb always aborts, so this never succeeds.
  ASSERT(ret <= 0);

  switch (SSL_get_error(ssl_.get(), ret)) {
  case SSL_ERROR_WANT_READ:
    if (read_ >= Config::TLS_MAX_CLIENT_HELLO) {
      return ParseState::Error;
    }
    if (read_ >= requested_read_bytes_) {
      requested_read_bytes_ =
          std::min<uint32_t>(2 * read_, Config::TLS_MAX_CLIENT_HELLO);
    }
    return ParseState::Continue;
  case SSL_ERROR_SSL:
    // ClientHello reached the select_certificate_cb (which set the verdict) and
    // then aborted as designed. If the verdict was written, we're done.
    return verdict_written_ ? ParseState::Done : ParseState::Error;
  default:
    return ParseState::Error;
  }
}

} // namespace RealityAuthenticator
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
