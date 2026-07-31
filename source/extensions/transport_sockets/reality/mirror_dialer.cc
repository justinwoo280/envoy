#include "source/extensions/transport_sockets/reality/mirror_dialer.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include <chrono>
#include <cstring>

#include "absl/status/status.h"
#include "envoy/network/address.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

namespace {
// SSL ex_data index to reach the MirrorDialer* from the msg_callback.
int mirrorDialerExDataIndex() {
  static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  return index;
}

// How long to keep reading after the ServerHello for the target's encrypted
// flight. A TLS 1.3 server sends the whole flight in the same burst as the
// ServerHello, so this normally never fires; it only bounds a target that
// stalls mid-flight.
constexpr std::chrono::milliseconds kFlightGrace{500};

// RFC 8446 4.1.3: a HelloRetryRequest is a ServerHello whose random is this
// fixed value. It must not be mistaken for the real ServerHello — injecting an
// HRR into the client-facing handshake would be nonsense, and its "flight" is a
// second ClientHello rather than the certificate flight we want to measure.
constexpr uint8_t kHelloRetryRequestRandom[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
    0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
    0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

// ServerHello layout: handshake header(4) + legacy_version(2) + random(32).
bool isHelloRetryRequest(const uint8_t* msg, size_t len) {
  return len >= 4 + 2 + 32 &&
         memcmp(msg + 4 + 2, kHelloRetryRequestRandom, sizeof(kHelloRetryRequestRandom)) == 0;
}
} // namespace

MirrorDialer::MirrorDialer(Event::Dispatcher& dispatcher, Network::DnsResolverSharedPtr resolver,
                           std::string host, uint32_t port, uint16_t group_id,
                           std::chrono::milliseconds timeout, CompleteCb on_complete)
    : dispatcher_(dispatcher), resolver_(std::move(resolver)), host_(std::move(host)), port_(port),
      group_id_(group_id), timeout_(timeout), on_complete_(std::move(on_complete)) {}

MirrorDialer::~MirrorDialer() {
  if (dns_query_ != nullptr) {
    dns_query_->cancel(Network::ActiveDnsQuery::CancelReason::QueryAbandoned);
    dns_query_ = nullptr;
  }
  if (file_event_ != nullptr) {
    file_event_.reset();
  }
  if (fd_ >= 0) {
    Api::OsSysCallsSingleton::get().close(fd_);
    fd_ = -1;
  }
}

void MirrorDialer::start() {
  timeout_timer_ = dispatcher_.createTimer([this]() { onTimeout(); });
  timeout_timer_->enableTimer(timeout_);

  // If host_ is already an IP literal, skip DNS.
  auto ip = Network::Utility::parseInternetAddressNoThrow(host_, static_cast<uint16_t>(port_));
  if (ip != nullptr) {
    connectTo(ip);
    return;
  }

  dns_query_ = resolver_->resolve(
      host_, Network::DnsLookupFamily::V4Preferred,
      [this](Network::DnsResolver::ResolutionStatus status, absl::string_view,
             std::list<Network::DnsResponse>&& response) {
        dns_query_ = nullptr;
        onResolve(status, std::move(response));
      });
}

void MirrorDialer::onResolve(Network::DnsResolver::ResolutionStatus status,
                             std::list<Network::DnsResponse>&& response) {
  if (status != Network::DnsResolver::ResolutionStatus::Completed || response.empty()) {
    ENVOY_LOG(debug, "REALITY mirror dial: DNS resolution failed for {}", host_);
    finishFailed();
    return;
  }
  auto address = Network::Utility::getAddressWithPort(*response.front().addrInfo().address_,
                                                      static_cast<uint16_t>(port_));
  connectTo(address);
}

void MirrorDialer::connectTo(const Network::Address::InstanceConstSharedPtr& address) {
  const sockaddr* sa = address->sockAddr();
  const socklen_t sa_len = address->sockAddrLen();
  auto& os = Api::OsSysCallsSingleton::get();

  // Non-blocking TCP socket (SOCK_NONBLOCK avoids a separate fcntl).
  auto sock_result = os.socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (sock_result.return_value_ < 0) {
    ENVOY_LOG(debug, "REALITY mirror dial: socket() failed errno={}", sock_result.errno_);
    finishFailed();
    return;
  }
  fd_ = sock_result.return_value_;

  auto conn_result = os.connect(fd_, sa, sa_len);
  if (conn_result.return_value_ != 0 && conn_result.errno_ != EINPROGRESS) {
    ENVOY_LOG(debug, "REALITY mirror dial: connect() failed errno={}", conn_result.errno_);
    finishFailed();
    return;
  }

  // Set up standalone BoringSSL client that captures the ServerHello.
  ssl_ctx_.reset(SSL_CTX_new(TLS_client_method()));
  SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS1_3_VERSION);
  // We only need the ServerHello; do not verify the mirror's certificate.
  SSL_CTX_set_verify(ssl_ctx_.get(), SSL_VERIFY_NONE, nullptr);

  ssl_.reset(SSL_new(ssl_ctx_.get()));
  SSL_set_connect_state(ssl_.get());
  SSL_set_tlsext_host_name(ssl_.get(), host_.c_str());
  // Dial the mirror with the same group the client negotiated, so the captured
  // ServerHello's key_share length matches what we will inject.
  const uint16_t group = group_id_;
  SSL_set1_group_ids(ssl_.get(), &group, 1);
  SSL_set_ex_data(ssl_.get(), mirrorDialerExDataIndex(), this);
  SSL_set_msg_callback(ssl_.get(), &MirrorDialer::msgCallback);
  SSL_set_msg_callback_arg(ssl_.get(), this);

  // Memory BIOs bridge SSL <-> the raw socket we pump manually.
  rbio_.reset(BIO_new(BIO_s_mem()));
  wbio_.reset(BIO_new(BIO_s_mem()));
  BIO_up_ref(rbio_.get());
  BIO_up_ref(wbio_.get());
  SSL_set0_rbio(ssl_.get(), rbio_.get());
  SSL_set0_wbio(ssl_.get(), wbio_.get());

  file_event_ = dispatcher_.createFileEvent(
      fd_,
      [this](uint32_t events) {
        onSocketEvent(events);
        return absl::OkStatus();
      },
      Event::FileTriggerType::Edge,
      Event::FileReadyType::Read | Event::FileReadyType::Write);
}

void MirrorDialer::msgCallback(int write_p, int /*version*/, int content_type, const void* buf,
                               size_t len, SSL* ssl, void* /*arg*/) {
  // Inbound (write_p==0) handshake messages only. BoringSSL invokes this from
  // its read path with the complete message including the 4-byte header, after
  // decryption for the post-ServerHello flight.
  if (write_p != 0 || content_type != SSL3_RT_HANDSHAKE || len < 1) {
    return;
  }
  auto* self = static_cast<MirrorDialer*>(SSL_get_ex_data(ssl, mirrorDialerExDataIndex()));
  if (self == nullptr) {
    return;
  }
  const uint8_t* p = static_cast<const uint8_t*>(buf);
  const uint32_t msg_len = static_cast<uint32_t>(len);
  switch (p[0]) {
  case SSL3_MT_SERVER_HELLO:
    if (self->capture_.server_hello.empty() && !isHelloRetryRequest(p, len)) {
      self->capture_.server_hello.assign(p, p + len);
    }
    break;
  case SSL3_MT_ENCRYPTED_EXTENSIONS:
    self->capture_.encrypted_extensions_len = msg_len;
    break;
  case SSL3_MT_CERTIFICATE:
    self->capture_.certificate_len = msg_len;
    break;
  case SSL3_MT_CERTIFICATE_REQUEST:
    self->capture_.saw_certificate_request = true;
    break;
  case SSL3_MT_CERTIFICATE_VERIFY:
    self->capture_.certificate_verify_len = msg_len;
    break;
  case SSL3_MT_FINISHED:
    self->capture_.finished_len = msg_len;
    // The flight is complete. Everything the handshaker needs is now known.
    self->capture_.flight_complete = true;
    break;
  default:
    break;
  }
}

void MirrorDialer::pumpOutbound() {
  auto& os = Api::OsSysCallsSingleton::get();
  char out[16384];
  int n;
  while ((n = BIO_read(wbio_.get(), out, sizeof(out))) > 0) {
    ssize_t off = 0;
    while (off < n) {
      auto rc = os.send(fd_, out + off, n - off, 0);
      if (rc.return_value_ > 0) {
        off += rc.return_value_;
      } else {
        // EAGAIN etc.: BoringSSL will re-emit on next drive; bail for now.
        return;
      }
    }
  }
}

void MirrorDialer::onSocketEvent(uint32_t /*events*/) {
  if (done_) {
    return;
  }
  auto& os = Api::OsSysCallsSingleton::get();

  // 1. Flush any pending SSL output (from BIO wbio_) to the socket.
  // 2. Read socket bytes into rbio_.
  // 3. Drive the handshake.
  pumpOutbound();

  // Pump inbound: socket -> rbio_.
  char in[16384];
  while (true) {
    auto rc = os.recv(fd_, in, sizeof(in), 0);
    if (rc.return_value_ > 0) {
      BIO_write(rbio_.get(), in, rc.return_value_);
    } else if (rc.return_value_ == 0) {
      break; // peer closed; drive once more below then finish if needed
    } else {
      break; // EAGAIN
    }
  }

  driveHandshake();
}

void MirrorDialer::driveHandshake() {
  if (done_) {
    return;
  }
  int rc = SSL_do_handshake(ssl_.get());

  // The target's whole second flight arrives in the same burst as its
  // ServerHello, so in the common case one drive yields both. Stop as soon as
  // the flight is complete: we deliberately do not send our own Finished, which
  // leaves the target with an abandoned handshake.
  if (capture_.flight_complete && !capture_.server_hello.empty()) {
    finish();
    return;
  }
  if (rc == 1) {
    // Handshake finished. Either we have the ServerHello (and possibly an
    // incomplete flight, e.g. a resumption without Certificate) or something is
    // very wrong.
    if (capture_.server_hello.empty()) {
      finishFailed();
    } else {
      finish();
    }
    return;
  }
  int err = SSL_get_error(ssl_.get(), rc);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
    // Flush any freshly produced output to the socket.
    pumpOutbound();
    // Once the ServerHello is in hand, bound the additional wait for the flight
    // so a stalled target degrades to "ServerHello only" rather than holding the
    // suspended client-facing handshake for the full dial timeout.
    if (!capture_.server_hello.empty() && flight_timer_ == nullptr) {
      flight_timer_ = dispatcher_.createTimer([this]() { onFlightTimeout(); });
      flight_timer_->enableTimer(kFlightGrace);
    }
    return; // wait for next socket event
  }
  // Hard error. If we already have the ServerHello, keep it: mirroring the
  // ServerHello alone is still strictly better than the static fallback.
  if (!capture_.server_hello.empty()) {
    ENVOY_LOG(debug, "REALITY mirror dial: error {} after ServerHello; flight not measured", err);
    finish();
    return;
  }
  ENVOY_LOG(debug, "REALITY mirror dial: handshake error {} (no ServerHello)", err);
  finishFailed();
}

void MirrorDialer::onTimeout() {
  ENVOY_LOG(debug, "REALITY mirror dial: timed out for {}", host_);
  if (!capture_.server_hello.empty()) {
    finish();
    return;
  }
  finishFailed();
}

void MirrorDialer::onFlightTimeout() {
  ENVOY_LOG(debug, "REALITY mirror dial: flight not received within grace period for {}", host_);
  finish();
}

void MirrorDialer::finishFailed() {
  capture_ = MirrorCapture{};
  finish();
}

void MirrorDialer::finish() {
  if (done_) {
    return;
  }
  done_ = true;
  if (timeout_timer_ != nullptr) {
    timeout_timer_->disableTimer();
  }
  if (flight_timer_ != nullptr) {
    flight_timer_->disableTimer();
  }
  if (file_event_ != nullptr) {
    file_event_.reset();
  }
  if (dns_query_ != nullptr) {
    dns_query_->cancel(Network::ActiveDnsQuery::CancelReason::QueryAbandoned);
    dns_query_ = nullptr;
  }
  if (fd_ >= 0) {
    Api::OsSysCallsSingleton::get().close(fd_);
    fd_ = -1;
  }
  // A partial flight is unusable for size matching: report it as not measured so
  // the handshaker emits its default certificate instead of a wrong-sized one.
  if (capture_.certificate_len == 0 || capture_.certificate_verify_len == 0) {
    capture_.flight_complete = false;
  }
  // Invoke the completion callback last; it may delete us.
  auto cb = std::move(on_complete_);
  cb(std::move(capture_));
}

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
