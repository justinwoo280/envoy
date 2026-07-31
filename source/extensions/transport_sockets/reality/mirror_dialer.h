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

// What a single mirror dial observed about the real target's second flight.
//
// `server_hello` is the plaintext ServerHello, injected byte-for-byte into the
// client-facing handshake. The remaining fields are the lengths (including the
// 4-byte handshake message header) of the target's *encrypted* flight messages,
// recovered after the dialer derives handshake keys and decrypts them.
//
// The lengths exist to close a traffic-analysis gap that mirroring the
// ServerHello alone does not: an observer of an authenticated REALITY session
// sees the ServerHello match the real site byte-for-byte, but then sees a
// ~350-byte encrypted certificate flight where the real site always serves
// several kilobytes. That is a single deterministic comparison, per connection,
// against a table the observer can build by crawling. RealityHandshaker uses
// `certificate_len` and `certificate_verify_len` to size its Ed25519 disguise
// leaf so the emitted flight matches the target's (see
// realityDisguiseCertTargetDerLen).
struct MirrorCapture {
  // Raw ServerHello handshake message including the 4-byte header. Empty means
  // the dial failed and the caller must fall back to a static ServerHello.
  std::vector<uint8_t> server_hello;

  // Decrypted flight message lengths, 0 when not observed.
  uint32_t encrypted_extensions_len{0};
  uint32_t certificate_len{0};
  uint32_t certificate_verify_len{0};
  uint32_t finished_len{0};

  // True once the target's Finished was seen, i.e. the flight above is complete
  // and the lengths may be used for size matching. When false the caller must
  // emit its default (unpadded) certificate rather than guess.
  bool flight_complete{false};

  // True if the target requested a client certificate, which adds a
  // CertificateRequest message we do not reproduce. Size matching is then
  // approximate; recorded so it can be logged rather than silently skewing.
  bool saw_certificate_request{false};
};

// MirrorDialer performs a live TLS handshake to a mirror target and captures its
// ServerHello plus the sizes of its encrypted second flight, entirely
// asynchronously on the owning connection's dispatcher.
//
// It is used during a REALITY handshake that has been suspended via
// ssl_select_cert_retry: while the client-facing handshake is parked (no worker
// thread blocked), the dialer connects to the real target, drives a standalone
// BoringSSL client handshake far enough to receive and decrypt the target's
// second flight, and reports the observations back.
//
// Reading the flight costs no extra round trip: a TLS 1.3 server sends
// ServerHello, ChangeCipherSpec and the encrypted flight in one burst, so the
// bytes have already arrived by the time the ServerHello is parsed. The dialer
// stops as soon as the target's Finished is seen and never sends its own
// Finished, so the target sees an abandoned handshake — the same thing REALITY's
// Go implementation leaves behind.
//
// Lifetime: owned by RealityHandshaker. The completion callback fires at most
// once, always on the dispatcher thread. On any failure/timeout it fires with an
// empty `server_hello` so the caller can fall back to a static ServerHello.
class MirrorDialer : public Logger::Loggable<Logger::Id::connection> {
public:
  using CompleteCb = std::function<void(MirrorCapture&&)>;

  MirrorDialer(Event::Dispatcher& dispatcher, Network::DnsResolverSharedPtr resolver,
               std::string host, uint32_t port, uint16_t group_id,
               std::chrono::milliseconds timeout, CompleteCb on_complete);
  ~MirrorDialer();

  // Begin the async dial. Must be called on the dispatcher thread.
  void start();

private:
  void finish();
  void finishFailed();
  void onResolve(Network::DnsResolver::ResolutionStatus status,
                 std::list<Network::DnsResponse>&& response);
  void connectTo(const Network::Address::InstanceConstSharedPtr& address);
  void onSocketEvent(uint32_t events);
  void driveHandshake();
  void pumpOutbound();
  void onTimeout();
  void onFlightTimeout();

  // msg_callback trampoline: captures the target's ServerHello and the lengths
  // of its encrypted flight messages.
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
  // Armed once the ServerHello is captured. Bounds how long we additionally wait
  // for the target's encrypted flight, so a target that stalls mid-flight
  // degrades to "ServerHello only" instead of holding the client-facing
  // handshake suspended until the overall dial timeout.
  Event::TimerPtr flight_timer_;
  Event::FileEventPtr file_event_;
  int fd_{-1};
  bssl::UniquePtr<SSL_CTX> ssl_ctx_;
  bssl::UniquePtr<SSL> ssl_;
  bssl::UniquePtr<BIO> rbio_; // network -> SSL
  bssl::UniquePtr<BIO> wbio_; // SSL -> network
  MirrorCapture capture_;
  bool done_{false};
};

using MirrorDialerPtr = std::unique_ptr<MirrorDialer>;

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
