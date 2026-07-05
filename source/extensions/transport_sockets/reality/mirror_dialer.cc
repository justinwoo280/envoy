#include "source/extensions/transport_sockets/reality/mirror_dialer.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

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
    ::close(fd_);
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
    finish({});
    return;
  }
  auto address = Network::Utility::getAddressWithPort(*response.front().addrInfo().address_,
                                                      static_cast<uint16_t>(port_));
  connectTo(address);
}

void MirrorDialer::connectTo(const Network::Address::InstanceConstSharedPtr& address) {
  const sockaddr* sa = address->sockAddr();
  const socklen_t sa_len = address->sockAddrLen();
  fd_ = ::socket(sa->sa_family, SOCK_STREAM, 0);
  if (fd_ < 0) {
    ENVOY_LOG(debug, "REALITY mirror dial: socket() failed");
    finish({});
    return;
  }
  // Non-blocking.
  int flags = ::fcntl(fd_, F_GETFL, 0);
  ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

  int rc = ::connect(fd_, sa, sa_len);
  if (rc != 0 && errno != EINPROGRESS) {
    ENVOY_LOG(debug, "REALITY mirror dial: connect() failed errno={}", errno);
    finish({});
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
      fd_, [this](uint32_t events) { onSocketEvent(events); }, Event::FileTriggerType::Edge,
      Event::FileReadyType::Read | Event::FileReadyType::Write);
}

void MirrorDialer::msgCallback(int write_p, int /*version*/, int content_type, const void* buf,
                               size_t len, SSL* ssl, void* /*arg*/) {
  // Inbound (write_p==0) handshake ServerHello (first byte == 2).
  if (write_p != 0 || content_type != SSL3_RT_HANDSHAKE || len < 1) {
    return;
  }
  const uint8_t* p = static_cast<const uint8_t*>(buf);
  if (p[0] != SSL3_MT_SERVER_HELLO) {
    return;
  }
  auto* self = static_cast<MirrorDialer*>(SSL_get_ex_data(ssl, mirrorDialerExDataIndex()));
  if (self != nullptr && self->captured_server_hello_.empty()) {
    self->captured_server_hello_.assign(p, p + len);
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

  // Pump outbound: drain wbio_ -> socket.
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
        break;
      }
    }
  }

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
  // We may already have the ServerHello even before the handshake fully
  // completes (BoringSSL parses it early). If so, we are done.
  if (!captured_server_hello_.empty()) {
    finish(std::move(captured_server_hello_));
    return;
  }
  if (rc == 1) {
    // Handshake finished but no ServerHello captured (shouldn't happen).
    finish({});
    return;
  }
  int err = SSL_get_error(ssl_.get(), rc);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
    // Flush any freshly produced output to the socket.
    auto& os = Api::OsSysCallsSingleton::get();
    char out[16384];
    int n;
    while ((n = BIO_read(wbio_.get(), out, sizeof(out))) > 0) {
      ssize_t off = 0;
      while (off < n) {
        auto sr = os.send(fd_, out + off, n - off, 0);
        if (sr.return_value_ > 0) {
          off += sr.return_value_;
        } else {
          break;
        }
      }
    }
    return; // wait for next socket event
  }
  // Hard error before we saw a ServerHello.
  ENVOY_LOG(debug, "REALITY mirror dial: handshake error {} (no ServerHello)", err);
  finish({});
}

void MirrorDialer::onTimeout() {
  ENVOY_LOG(debug, "REALITY mirror dial: timed out for {}", host_);
  finish({});
}

void MirrorDialer::finish(std::vector<uint8_t>&& server_hello) {
  if (done_) {
    return;
  }
  done_ = true;
  if (timeout_timer_ != nullptr) {
    timeout_timer_->disableTimer();
  }
  if (file_event_ != nullptr) {
    file_event_.reset();
  }
  if (dns_query_ != nullptr) {
    dns_query_->cancel(Network::ActiveDnsQuery::CancelReason::QueryAbandoned);
    dns_query_ = nullptr;
  }
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  // Invoke the completion callback last; it may delete us.
  auto cb = std::move(on_complete_);
  cb(std::move(server_hello));
}

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
