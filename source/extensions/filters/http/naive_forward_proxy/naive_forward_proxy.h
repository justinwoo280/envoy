#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "envoy/api/api.h"
#include "envoy/config/core/v3/extension.pb.h"
#include "envoy/extensions/filters/http/naive_forward_proxy/v3/naive_forward_proxy.pb.h"
#include "envoy/http/filter.h"
#include "envoy/network/connection.h"
#include "envoy/network/dns.h"
#include "envoy/network/dns_resolver.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/file_event.h"
#include "envoy/server/factory_context.h"

#include "source/common/common/linked_object.h"
#include "source/common/common/logger.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"
#include "source/extensions/filters/http/naive_forward_proxy/naive_padding_framer.h"
#include "source/extensions/filters/http/naive_forward_proxy/uot_framer.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

using NaiveForwardProxyConfig =
    envoy::extensions::filters::http::naive_forward_proxy::v3::NaiveForwardProxy;

class Config {
public:
  Config(const NaiveForwardProxyConfig& proto_config, Server::Configuration::FactoryContext& context);

  const std::string& username() const { return username_; }
  const std::string& password() const { return password_; }
  bool fastOpen() const { return fast_open_; }
  uint32_t maxPaddingSize() const { return max_padding_size_; }
  std::chrono::milliseconds idleTimeout() const { return idle_timeout_; }
  std::chrono::milliseconds tunnelTimeout() const { return tunnel_timeout_; }

  // Create a DNS resolver bound to the given (worker-thread) dispatcher. The
  // resolver MUST live on and be driven by the same thread that calls resolve()
  // on it; a single shared resolver created on the main thread and used from
  // workers corrupts the heap (c-ares fd/epoll state is not thread-safe).
  Network::DnsResolverSharedPtr createDnsResolver(Event::Dispatcher& dispatcher) const;

private:
  std::string username_;
  std::string password_;
  bool fast_open_;
  uint32_t max_padding_size_;
  std::chrono::milliseconds idle_timeout_;
  std::chrono::milliseconds tunnel_timeout_;
  Api::Api& api_;
  // Declared before the factory because the factory is initialized from it.
  envoy::config::core::v3::TypedExtensionConfig dns_resolver_config_;
  Network::DnsResolverFactory& dns_resolver_factory_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

// NaiveForwardProxyFilter implements a NaiveProxy-compatible forward proxy
// as an Envoy HTTP filter. It handles:
//
// 1. HTTP CONNECT for TCP tunneling (with Variant1 padding)
// 2. HTTP CONNECT to UoT magic address for UDP relay (UoT v2 framing)
//
// The filter intercepts CONNECT requests, authenticates the client, and
// creates upstream connections (TCP or UDP) to relay traffic.
class NaiveForwardProxyFilter : public Http::PassThroughDecoderFilter,
                                public Network::ConnectionCallbacks,
                                Logger::Loggable<Logger::Id::filter> {
public:
  NaiveForwardProxyFilter(ConfigSharedPtr config);
  ~NaiveForwardProxyFilter() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) override;
  void onDestroy() override;

  // Network::ConnectionCallbacks (for TCP upstream)
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  // File event callback for UDP socket reads (registered via createFileEvent).
  void onFileEvent(uint32_t events);

private:
  enum class Mode { kNone, kTcp, kUdp };
  enum class State {
    kIdle,
    kAuthenticated,
    kDnsResolving,
    kTcpConnecting,
    kWaitUotHandshake,
    kUdpResolving,
    kTunneling,
    kClosed,
  };

  // ---- decodeHeaders helpers ----
  bool authenticate(const Http::RequestHeaderMap& headers);
  static bool constantTimeEquals(absl::string_view a, absl::string_view b);
  void send200OK();
  void sendError(Http::Code code, absl::string_view body);
  // Returns false if the :authority is missing/malformed (untrusted input).
  bool extractTarget(const Http::RequestHeaderMap& headers);
  void parsePaddingHeader(const Http::RequestHeaderMap& headers);
  bool isUotRequest() const;

  // ---- TCP path ----
  void startTcpDnsResolve();
  void onTcpDnsResolveComplete(Network::DnsResolver::ResolutionStatus status,
                                absl::string_view details,
                                std::list<Network::DnsResponse>&& response);
  void startTcpConnect(Network::Address::InstanceConstSharedPtr address);
  void onTcpUpstreamEvent(Network::ConnectionEvent event);
  void relayClientToTcpUpstream(Buffer::Instance& data, bool end_stream);
  // Flush client bytes buffered before the upstream connected (fast-open race).
  void flushPendingToUpstream();
  void relayTcpUpstreamToClient(Buffer::Instance& data, bool end_stream);

  // TCP upstream read filter.
  //
  // The upstream connection is torn down via dispatcher().deferredDelete(), so
  // it (and this read filter) can outlive the owning NaiveForwardProxyFilter,
  // which the HTTP layer destroys synchronously on stream reset. A raw
  // back-reference would therefore dangle and any late onData() would invoke a
  // virtual on a destroyed object ("pure virtual function called"). Guard with
  // a shared "alive" flag that the parent clears in closeAll()/its destructor.
  class TcpReadFilter : public Network::ReadFilter {
  public:
    TcpReadFilter(NaiveForwardProxyFilter& parent, std::shared_ptr<bool> alive)
        : parent_(parent), alive_(std::move(alive)) {}
    Network::FilterStatus onNewConnection() override { return Network::FilterStatus::Continue; }
    Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override {
      if (alive_ && *alive_) {
        parent_.relayTcpUpstreamToClient(data, end_stream);
      }
      return Network::FilterStatus::StopIteration;
    }
    void initializeReadFilterCallbacks(Network::ReadFilterCallbacks&) override {}

  private:
    NaiveForwardProxyFilter& parent_;
    std::shared_ptr<bool> alive_;
  };

  // ---- UDP path ----
  void processUotData(Buffer::Instance& data);
  void onUotHandshake(const UotFrame& frame);
  void startUdpDnsResolve(const HostPort& dest);
  void onUdpDnsResolveComplete(Network::DnsResolver::ResolutionStatus status,
                                absl::string_view details,
                                std::list<Network::DnsResponse>&& response);
  void createUdpSocket(Network::Address::InstanceConstSharedPtr address);
  void onUdpReadable();
  void relayUotFrameToUdp(const UotFrame& frame);
  void sendUotHandshakeEcho();

  // ---- Padding helpers ----
  void stripPadding(Buffer::Instance& in, std::string& out);
  std::string addPadding(std::string_view payload);
  uint8_t randomPaddingSize() const;

  // ---- Common ----
  void closeAll();
  void scheduleIdleTimeout();

  // The worker-thread dispatcher this filter (and its stream) runs on. All
  // per-stream network objects (upstream connection, file events, timers) and
  // their deferredDelete MUST use this dispatcher, NOT the main-thread
  // dispatcher held by Config: using the main-thread dispatcher creates and
  // tears down connections on a different thread than the one operating them,
  // corrupting the heap (observed as pure-virtual/SIGSEGV under load).
  Event::Dispatcher& dispatcher() { return decoder_callbacks_->dispatcher(); }

  ConfigSharedPtr config_;

  Mode mode_ = Mode::kNone;
  State state_ = State::kIdle;

  // Target extracted from CONNECT :authority
  std::string target_host_;
  uint16_t target_port_ = 0;

  // Padding
  bool padding_enabled_ = false;
  PaddingFramer padding_decoder_; // client → server (strip)
  PaddingFramer padding_encoder_; // server → client (add)

  // Shared liveness flag handed to TcpReadFilter so a deferred-deleted upstream
  // connection's late callbacks become no-ops after this filter is destroyed.
  std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);

  // TCP upstream
  Network::ClientConnectionPtr tcp_upstream_;
  bool tcp_upstream_connected_ = false;
  bool client_half_closed_ = false;
  bool upstream_half_closed_ = false;
  // Plaintext (padding already stripped) received from the client before the
  // upstream finished connecting; flushed by flushPendingToUpstream() on the
  // Connected event. Prevents losing the first payload in fast-open mode.
  Buffer::OwnedImpl pending_upstream_data_;

  // UDP upstream (syscalls via Api::OsSysCallsSingleton::get() at each use site)
  int udp_fd_ = -1;
  Event::FileEventPtr udp_file_event_;
  Network::Address::InstanceConstSharedPtr udp_dest_address_;
  bool udp_is_connect_ = true; // isConnect mode from handshake
  HostPort udp_dest_;          // destination from UoT handshake
  UotDecoder uot_decoder_;
  bool uot_handshake_echo_sent_ = false;

  // DNS. The resolver is created lazily on this filter's worker thread (never
  // shared across threads) and returns the worker-thread-bound resolver.
  Network::DnsResolver& dnsResolver();
  Network::DnsResolverSharedPtr dns_resolver_;
  Network::ActiveDnsQuery* dns_query_ = nullptr;

  // Idle timer
  Event::TimerPtr idle_timer_;
};

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
