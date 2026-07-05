#pragma once

#include <openssl/ssl.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "envoy/event/dispatcher.h"
#include "envoy/event/file_event.h"
#include "envoy/event/timer.h"
#include "envoy/network/dns.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

// MirrorDialer performs a live TLS handshake to a mirror target and captures its
// ServerHello, entirely asynchronously on the owning connection's dispatcher.
//
// It is used during a REALITY handshake that has been suspended via
// ssl_select_cert_retry: while the client-facing handshake is parked (no worker
// thread blocked), the dialer connects to the real target, drives a standalone
// BoringSSL client handshake far enough to receive the target's ServerHello,
// captures those raw bytes (via SSL_set_msg_callback), and reports them back so
// the handshaker can inject them into the client-facing ServerHello.
//
// The dialer only needs the ServerHello (its plaintext extension structure is
// what defeats fingerprinting); it does not complete the mirror handshake and
// does not derive any mirror keys.
//
// Lifetime: owned by RealityHandshaker. The completion callback fires at most
// once, always on the dispatcher thread. On any failure/timeout it fires with
// an empty vector so the caller can fall back to a static ServerHello.
class MirrorDialer : public Logger::Loggable<Logger::Id::connection> {
public:
  // on_complete(server_hello_bytes): non-empty = captured ServerHello (raw
  // handshake message incl. 4-byte header); empty = failed/timed out.
  using CompleteCb = std::function<void(std::vector<uint8_t>&&)>;

  MirrorDialer(Event::Dispatcher& dispatcher, Network::DnsResolverSharedPtr resolver,
               std::string host, uint32_t port, uint16_t group_id,
               std::chrono::milliseconds timeout, CompleteCb on_complete);
  ~MirrorDialer();

  // Begin the async dial. Must be called on the dispatcher thread.
  void start();

private:
  void finish(std::vector<uint8_t>&& server_hello);
  void onResolve(Network::DnsResolver::ResolutionStatus status,
                 std::list<Network::DnsResponse>&& response);
  void connectTo(const Network::Address::InstanceConstSharedPtr& address);
  void onSocketEvent(uint32_t events);
  void driveHandshake();
  void onTimeout();

  // msg_callback trampoline: captures the target's ServerHello.
  static void msgCallback(int write_p, int version, int content_type, const void* buf, size_t len,
                          SSL* ssl, void* arg);

  Event::Dispatcher& dispatcher_;
  Network::DnsResolverSharedPtr resolver_;
  const std::string host_;
  const uint32_t port_;
  const uint16_t group_id_;
  const std::chrono::milliseconds timeout_;
  CompleteCb on_complete_;

  Network::ActiveDnsQuery* dns_query_{nullptr};
  Event::TimerPtr timeout_timer_;
  Event::FileEventPtr file_event_;
  int fd_{-1};
  bssl::UniquePtr<SSL_CTX> ssl_ctx_;
  bssl::UniquePtr<SSL> ssl_;
  bssl::UniquePtr<BIO> rbio_; // network -> SSL
  bssl::UniquePtr<BIO> wbio_; // SSL -> network
  std::vector<uint8_t> captured_server_hello_;
  bool done_{false};
};

using MirrorDialerPtr = std::unique_ptr<MirrorDialer>;

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
