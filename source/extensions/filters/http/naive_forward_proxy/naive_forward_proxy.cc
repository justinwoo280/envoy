#include "source/extensions/filters/http/naive_forward_proxy/naive_forward_proxy.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>

#include "envoy/common/exception.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/network/socket.h"

#include "source/common/api/os_sys_calls_impl.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/base64.h"
#include "source/common/common/utility.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/headers.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/dns_resolver/dns_factory_util.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/common/network/socket_impl.h"
#include "source/common/network/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

namespace {
constexpr absl::string_view kPaddingHeader = "padding";
constexpr std::chrono::milliseconds kDefaultIdleTimeout = std::chrono::minutes(5);
constexpr std::chrono::milliseconds kDefaultTunnelTimeout = std::chrono::minutes(15);
constexpr int kUdpRecvBufSize = 65536;
} // namespace

// ---- Config ----

Config::Config(const NaiveForwardProxyConfig& proto_config,
               Server::Configuration::FactoryContext& context)
    : username_(proto_config.username()), password_(proto_config.password()),
      fast_open_(proto_config.fast_open()),
      max_padding_size_(proto_config.max_padding_size()),
      api_(context.serverFactoryContext().api()),
      dns_resolver_factory_(Network::createDefaultDnsResolverFactory(dns_resolver_config_)) {
  idle_timeout_ = proto_config.has_idle_timeout()
                      ? std::chrono::milliseconds(
                            DurationUtil::durationToMilliseconds(proto_config.idle_timeout()))
                      : kDefaultIdleTimeout;
  tunnel_timeout_ = proto_config.has_tunnel_timeout()
                        ? std::chrono::milliseconds(
                              DurationUtil::durationToMilliseconds(proto_config.tunnel_timeout()))
                        : kDefaultTunnelTimeout;
  // Note: the DNS resolver is NOT created here. It is created per worker thread
  // via createDnsResolver(), because a c-ares resolver must be created on and
  // driven by the same thread that resolves against it. See createDnsResolver().
}

Network::DnsResolverSharedPtr Config::createDnsResolver(Event::Dispatcher& dispatcher) const {
  return THROW_OR_RETURN_VALUE(
      dns_resolver_factory_.createDnsResolver(dispatcher, api_, dns_resolver_config_),
      Network::DnsResolverSharedPtr);
}

Network::DnsResolver& NaiveForwardProxyFilter::dnsResolver() {
  // Lazily create a resolver bound to this filter's worker-thread dispatcher.
  if (!dns_resolver_) {
    dns_resolver_ = config_->createDnsResolver(dispatcher());
  }
  return *dns_resolver_;
}

// ---- Filter ----

NaiveForwardProxyFilter::NaiveForwardProxyFilter(ConfigSharedPtr config) : config_(config) {}

NaiveForwardProxyFilter::~NaiveForwardProxyFilter() { closeAll(); }

void NaiveForwardProxyFilter::onDestroy() { closeAll(); }

// ---- decodeHeaders ----

Http::FilterHeadersStatus
NaiveForwardProxyFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  if (!Http::HeaderUtility::isConnect(headers)) {
    return Http::FilterHeadersStatus::Continue;
  }

  // Authenticate before doing any work for the request.
  if (!authenticate(headers)) {
    sendError(Http::Code::ProxyAuthenticationRequired, "Authentication required");
    return Http::FilterHeadersStatus::StopIteration;
  }

  // Extract target from :authority (untrusted). Reject malformed authorities
  // instead of crashing on bad input.
  if (!extractTarget(headers)) {
    sendError(Http::Code::BadRequest, "Invalid target authority");
    return Http::FilterHeadersStatus::StopIteration;
  }

  // Parse padding header
  parsePaddingHeader(headers);

  // Determine mode
  if (isUotRequest()) {
    mode_ = Mode::kUdp;
    state_ = State::kAuthenticated;
  } else {
    mode_ = Mode::kTcp;
    state_ = State::kAuthenticated;
  }

  // Fast Open: send 200 OK immediately
  if (config_->fastOpen()) {
    send200OK();
  }

  if (mode_ == Mode::kTcp) {
    ENVOY_LOG(info, "NAIVE_DIAG decodeHeaders: CONNECT tcp target={}:{}", target_host_,
              target_port_);
    // Start DNS resolution for TCP target
    startTcpDnsResolve();
  } else {
    // UDP: wait for first DATA frame containing UoT handshake
    state_ = State::kWaitUotHandshake;
  }

  return Http::FilterHeadersStatus::StopIteration;
}

Http::FilterDataStatus NaiveForwardProxyFilter::decodeData(Buffer::Instance& data, bool end_stream) {
  if (state_ == State::kClosed) {
    return Http::FilterDataStatus::StopIterationNoBuffer;
  }

  if (mode_ == Mode::kTcp) {
    // TCP relay: strip padding → write to upstream
    relayClientToTcpUpstream(data, end_stream);
  } else if (mode_ == Mode::kUdp) {
    // UDP relay: strip padding → UoT decode → UDP send
    processUotData(data);
  }

  if (end_stream) {
    client_half_closed_ = true;
    if (mode_ == Mode::kTcp && tcp_upstream_) {
      // Half-close the upstream by writing end_stream (half-close was enabled
      // via enableHalfClose(true) on connect).
      Buffer::OwnedImpl empty;
      tcp_upstream_->write(empty, true);
    }
    // For UDP, closing the H2 stream means the UoT session is done
    if (mode_ == Mode::kUdp) {
      closeAll();
    }
  }

  return Http::FilterDataStatus::StopIterationNoBuffer;
}

// ---- Authentication ----

bool NaiveForwardProxyFilter::authenticate(const Http::RequestHeaderMap& headers) {
  if (config_->username().empty()) {
    return true; // No auth required
  }

  const auto auth = headers.get(Http::Headers::get().ProxyAuthorization);
  if (auth.empty()) {
    return false;
  }

  auto value = auth[0]->value().getStringView();
  if (!value.starts_with("Basic ")) {
    return false;
  }

  auto encoded = value.substr(6);
  auto decoded = Base64::decode(std::string(encoded));
  auto colon_pos = decoded.find(':');
  if (colon_pos == std::string::npos) {
    return false;
  }

  auto user = decoded.substr(0, colon_pos);
  auto pass = decoded.substr(colon_pos + 1);
  // Constant-time comparison to avoid leaking username/password length or
  // content via response timing (mitigates credential brute-forcing).
  return constantTimeEquals(user, config_->username()) &&
         constantTimeEquals(pass, config_->password());
}

// Length-independent constant-time string comparison. Returns true iff equal.
// Note: the comparison time still depends on the *inputs'* lengths, but not on
// how many leading bytes match, which is the property we need here.
bool NaiveForwardProxyFilter::constantTimeEquals(absl::string_view a,
                                                 absl::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); i++) {
    diff |= static_cast<uint8_t>(a[i]) ^ static_cast<uint8_t>(b[i]);
  }
  return diff == 0;
}

// ---- Target extraction ----

bool NaiveForwardProxyFilter::extractTarget(const Http::RequestHeaderMap& headers) {
  const auto* host = headers.Host();
  if (host == nullptr) {
    return false;
  }
  auto authority = host->value().getStringView();
  if (authority.empty()) {
    return false;
  }
  auto colon = authority.rfind(':');
  if (colon != absl::string_view::npos) {
    // Port comes from the untrusted :authority. std::stoi would THROW on
    // non-numeric or out-of-range input (a crash/DoS vector). Parse safely and
    // validate the range.
    uint32_t port = 0;
    auto port_str = authority.substr(colon + 1);
    if (!absl::SimpleAtoi(port_str, &port) || port > 65535) {
      return false;
    }
    target_host_ = std::string(authority.substr(0, colon));
    // Port 0 is normally rejected (bogus for a TCP CONNECT), but the UoT magic
    // address is always requested with port 0 by the naive client because the
    // real per-datagram destination travels inside the UoT frames, not in the
    // CONNECT authority. Accept port 0 only for the UoT magic hosts; the value
    // is unused for UDP mode. For any other host, port 0 is still an error.
    if (port == 0 && !isUotRequest()) {
      return false;
    }
    target_port_ = static_cast<uint16_t>(port);
  } else {
    target_host_ = std::string(authority);
    target_port_ = 443; // default
  }
  if (target_host_.empty()) {
    return false;
  }
  return true;
}

void NaiveForwardProxyFilter::parsePaddingHeader(const Http::RequestHeaderMap& headers) {
  const auto padding = headers.get(Http::LowerCaseString(std::string(kPaddingHeader)));
  if (!padding.empty()) {
    auto value = padding[0]->value().getStringView();
    if (value.find("variant1") != absl::string_view::npos) {
      padding_enabled_ = true;
    }
  }
}

bool NaiveForwardProxyFilter::isUotRequest() const {
  return target_host_ == kUotMagicAddress || target_host_ == kUotLegacyMagicAddress;
}

// ---- Response helpers ----

void NaiveForwardProxyFilter::send200OK() {
  auto response = Http::ResponseHeaderMapImpl::create();
  response->setStatus(static_cast<uint64_t>(Http::Code::OK));
  if (padding_enabled_) {
    response->addCopy(Http::LowerCaseString(std::string(kPaddingHeader)), "variant1");
  }
  decoder_callbacks_->encodeHeaders(std::move(response), false,
                                    "naive_forward_proxy_tunnel_established");
}

void NaiveForwardProxyFilter::sendError(Http::Code code, absl::string_view body) {
  decoder_callbacks_->sendLocalReply(code, body, nullptr, std::nullopt,
                                     "naive_forward_proxy_error");
}

// ---- TCP path ----

void NaiveForwardProxyFilter::startTcpDnsResolve() {
  state_ = State::kDnsResolving;

  // Check if it's already an IP address
  auto address = Network::Utility::parseInternetAddressNoThrow(target_host_, target_port_);
  if (address) {
    startTcpConnect(address);
    return;
  }

  // Async DNS resolution
  dns_query_ = dnsResolver().resolve(
      target_host_, Network::DnsLookupFamily::V4Preferred,
      [this](Network::DnsResolver::ResolutionStatus status, absl::string_view details,
             std::list<Network::DnsResponse>&& response) -> void {
        dns_query_ = nullptr;
        onTcpDnsResolveComplete(status, details, std::move(response));
      });
}

void NaiveForwardProxyFilter::onTcpDnsResolveComplete(
    Network::DnsResolver::ResolutionStatus status, absl::string_view details,
    std::list<Network::DnsResponse>&& response) {
  if (status != Network::DnsResolver::ResolutionStatus::Completed || response.empty()) {
    ENVOY_LOG(warn, "naive_forward_proxy: DNS resolution failed for {}: {}", target_host_,
              details);
    if (!config_->fastOpen()) {
      sendError(Http::Code::BadGateway, "DNS resolution failed");
    } else {
      // 200 OK already sent, reset the stream
      decoder_callbacks_->resetStream(Http::StreamResetReason::ConnectError, "DNS failed");
    }
    state_ = State::kClosed;
    return;
  }

  auto address = Network::Utility::getAddressWithPort(*response.front().addrInfo().address_,
                                                       target_port_);
  startTcpConnect(address);
}

void NaiveForwardProxyFilter::startTcpConnect(Network::Address::InstanceConstSharedPtr address) {
  state_ = State::kTcpConnecting;

  // Create a plaintext TCP transport socket for the upstream tunnel.
  auto transport_socket = std::make_unique<Network::RawBufferSocket>();

  tcp_upstream_ = dispatcher().createClientConnection(
      address, nullptr, std::move(transport_socket), nullptr, nullptr);
  tcp_upstream_->enableHalfClose(true);
  tcp_upstream_->addConnectionCallbacks(*this);
  tcp_upstream_->addReadFilter(std::make_shared<TcpReadFilter>(*this, alive_));
  ENVOY_LOG(info, "NAIVE_DIAG startTcpConnect: connecting to {} (fast_open={})",
            address->asString(), config_->fastOpen());
  tcp_upstream_->connect();
  ENVOY_LOG(info, "NAIVE_DIAG startTcpConnect: connect() returned, state={}",
            static_cast<int>(tcp_upstream_->state()));
}

void NaiveForwardProxyFilter::onEvent(Network::ConnectionEvent event) {
  onTcpUpstreamEvent(event);
}

void NaiveForwardProxyFilter::onTcpUpstreamEvent(Network::ConnectionEvent event) {
  ENVOY_LOG(info, "NAIVE_DIAG onTcpUpstreamEvent: event={} state={}",
            static_cast<int>(event), static_cast<int>(state_));
  if (event == Network::ConnectionEvent::Connected) {
    tcp_upstream_connected_ = true;
    if (!config_->fastOpen()) {
      send200OK();
      ENVOY_LOG(info, "NAIVE_DIAG onTcpUpstreamEvent: send200OK done");
    }
    state_ = State::kTunneling;
    scheduleIdleTimeout();
  } else if (event == Network::ConnectionEvent::RemoteClose ||
             event == Network::ConnectionEvent::LocalClose) {
    if (state_ == State::kTcpConnecting && !config_->fastOpen()) {
      sendError(Http::Code::BadGateway, "Upstream connect failed");
    } else if (state_ == State::kTcpConnecting && config_->fastOpen()) {
      decoder_callbacks_->resetStream(Http::StreamResetReason::ConnectError,
                                      "Upstream connect failed");
    } else if (state_ == State::kTunneling) {
      // Close the downstream
      Buffer::OwnedImpl empty;
      decoder_callbacks_->encodeData(empty, true);
    }
    state_ = State::kClosed;
  }
}

void NaiveForwardProxyFilter::relayClientToTcpUpstream(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(info, "NAIVE_DIAG relayClientToTcpUpstream: len={} end_stream={} conn={} connected={}",
            data.length(), end_stream, tcp_upstream_ != nullptr, tcp_upstream_connected_);
  if (!tcp_upstream_ || !tcp_upstream_connected_) {
    return;
  }

  // Strip padding if enabled
  if (padding_enabled_ && padding_decoder_.decodePaddingActive()) {
    std::string payload;
    auto* bytes = reinterpret_cast<const uint8_t*>(data.linearize(data.length()));
    padding_decoder_.decode(bytes, data.length(), &payload);
    Buffer::OwnedImpl buf;
    buf.add(payload.data(), payload.size());
    tcp_upstream_->write(buf, end_stream && client_half_closed_);
  } else {
    // Pass-through
    tcp_upstream_->write(data, end_stream && client_half_closed_);
  }
}

void NaiveForwardProxyFilter::relayTcpUpstreamToClient(Buffer::Instance& data, bool end_stream) {
  // IMPORTANT: encodeData() with end_stream=true can synchronously reset the
  // downstream stream, which destroys THIS filter before encodeData() returns.
  // Therefore update all member state BEFORE calling encodeData(), and never
  // touch any member (including implicit `this`) afterwards on the end_stream
  // path. Reordering here removes a use-after-free that manifested under load
  // as alternating "pure virtual function called" / SIGSEGV during bursts of
  // concurrent stream teardown.
  if (end_stream) {
    upstream_half_closed_ = true;
    state_ = State::kClosed;
  }

  if (padding_enabled_ && padding_encoder_.encodePaddingActive()) {
    // Add padding
    auto* bytes = reinterpret_cast<const uint8_t*>(data.linearize(data.length()));
    std::string_view payload(reinterpret_cast<const char*>(bytes), data.length());
    std::string padded = padding_encoder_.encode(payload, randomPaddingSize());
    Buffer::OwnedImpl buf;
    buf.add(padded.data(), padded.size());
    decoder_callbacks_->encodeData(buf, end_stream);
    // do not touch members past this point on the end_stream path
    return;
  }
  decoder_callbacks_->encodeData(data, end_stream);
  // do not touch members past this point on the end_stream path
}

// ---- UDP path ----

void NaiveForwardProxyFilter::processUotData(Buffer::Instance& data) {
  // Strip padding if enabled
  std::string raw_data;
  if (padding_enabled_ && padding_decoder_.decodePaddingActive()) {
    auto* bytes = reinterpret_cast<const uint8_t*>(data.linearize(data.length()));
    padding_decoder_.decode(bytes, data.length(), &raw_data);
  } else {
    raw_data.assign(static_cast<const char*>(data.linearize(data.length())), data.length());
  }

  // Feed into UoT decoder
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(raw_data.data());
  size_t pos = 0;
  while (pos < raw_data.size()) {
    size_t consumed = 0;
    auto frame = uot_decoder_.feed(bytes + pos, raw_data.size() - pos, &consumed);
    pos += consumed;
    if (!frame) {
      if (uot_decoder_.hasError()) {
        ENVOY_LOG(error, "naive_forward_proxy: UoT decoder error");
        decoder_callbacks_->resetStream(Http::StreamResetReason::ProtocolError,
                                        "UoT decode error");
        closeAll();
        return;
      }
      break;
    }

    if (frame->type == FrameType::kHandshake) {
      onUotHandshake(*frame);
    } else if (frame->type == FrameType::kData) {
      if (state_ == State::kTunneling) {
        relayUotFrameToUdp(*frame);
      }
    }
  }
}

void NaiveForwardProxyFilter::onUotHandshake(const UotFrame& frame) {
  udp_is_connect_ = frame.is_connect;
  udp_dest_ = frame.destination;

  ENVOY_LOG(info, "naive_forward_proxy: UoT handshake: isConnect={} dest={}:{}",
            udp_is_connect_, udp_dest_.host, udp_dest_.port);

  // Send handshake echo back to client (with padding)
  sendUotHandshakeEcho();

  // Start DNS resolution for UDP destination
  startUdpDnsResolve(udp_dest_);
}

void NaiveForwardProxyFilter::sendUotHandshakeEcho() {
  if (uot_handshake_echo_sent_) return;
  uot_handshake_echo_sent_ = true;

  std::string echo = encodeHandshake(udp_is_connect_, udp_dest_);
  if (padding_enabled_ && padding_encoder_.encodePaddingActive()) {
    echo = padding_encoder_.encode(echo, randomPaddingSize());
  }
  Buffer::OwnedImpl buf;
  buf.add(echo.data(), echo.size());
  decoder_callbacks_->encodeData(buf, false);
}

void NaiveForwardProxyFilter::startUdpDnsResolve(const HostPort& dest) {
  state_ = State::kUdpResolving;

  // Check if it's already an IP address
  auto address = Network::Utility::parseInternetAddressNoThrow(dest.host, dest.port);
  if (address) {
    createUdpSocket(address);
    return;
  }

  dns_query_ = dnsResolver().resolve(
      dest.host, Network::DnsLookupFamily::V4Preferred,
      [this](Network::DnsResolver::ResolutionStatus status, absl::string_view details,
             std::list<Network::DnsResponse>&& response) -> void {
        dns_query_ = nullptr;
        onUdpDnsResolveComplete(status, details, std::move(response));
      });
}

void NaiveForwardProxyFilter::onUdpDnsResolveComplete(
    Network::DnsResolver::ResolutionStatus status, absl::string_view details,
    std::list<Network::DnsResponse>&& response) {
  if (status != Network::DnsResolver::ResolutionStatus::Completed || response.empty()) {
    ENVOY_LOG(warn, "naive_forward_proxy: UDP DNS resolution failed for {}: {}",
              udp_dest_.host, details);
    decoder_callbacks_->resetStream(Http::StreamResetReason::ConnectError, "UDP DNS failed");
    state_ = State::kClosed;
    return;
  }

  auto address = Network::Utility::getAddressWithPort(*response.front().addrInfo().address_,
                                                       udp_dest_.port);
  createUdpSocket(address);
}

void NaiveForwardProxyFilter::createUdpSocket(Network::Address::InstanceConstSharedPtr address) {
  udp_dest_address_ = address;

  // Create a UDP socket
  // For isConnect=true: connected UDP socket (one destination)
  // For isConnect=false: unconnected UDP socket (multiple destinations)
  if (udp_is_connect_) {
    // Connected UDP socket (non-blocking: driven by the dispatcher's FileEvent).
    auto& os_syscalls = Api::OsSysCallsSingleton::get();
    auto sock_result = os_syscalls.socket(address->ip()->version() == Network::Address::IpVersion::v4
                                               ? AF_INET
                                               : AF_INET6,
                                           SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sock_result.return_value_ < 0) {
      ENVOY_LOG(error, "naive_forward_proxy: failed to create UDP socket");
      decoder_callbacks_->resetStream(Http::StreamResetReason::ConnectError,
                                      "UDP socket creation failed");
      return;
    }
    udp_fd_ = sock_result.return_value_;

    // Connect the UDP socket. Address already exposes a ready sockaddr.
    auto connect_result =
        os_syscalls.connect(udp_fd_, address->sockAddr(), address->sockAddrLen());
    if (connect_result.return_value_ < 0) {
      ENVOY_LOG(error, "naive_forward_proxy: UDP connect failed");
      os_syscalls.close(udp_fd_);
      udp_fd_ = -1;
      decoder_callbacks_->resetStream(Http::StreamResetReason::ConnectError,
                                      "UDP connect failed");
      return;
    }
  } else {
    // Unconnected UDP socket. Create it non-blocking: Envoy's dispatcher drives
    // it via an edge-triggered FileEvent and onUdpReadable() loops recvmsg until
    // EAGAIN, so a blocking fd would stall the whole worker thread on the last
    // recvmsg.
    auto& os_syscalls = Api::OsSysCallsSingleton::get();
    auto sock_result =
        os_syscalls.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sock_result.return_value_ < 0) {
      ENVOY_LOG(error, "naive_forward_proxy: failed to create UDP socket");
      decoder_callbacks_->resetStream(Http::StreamResetReason::ConnectError,
                                      "UDP socket creation failed");
      return;
    }
    udp_fd_ = sock_result.return_value_;
  }

  // Register FileEvent for reads
  udp_file_event_ = dispatcher().createFileEvent(
      udp_fd_,
      [this](uint32_t events) -> absl::Status {
        onFileEvent(events);
        return absl::OkStatus();
      },
      Event::FileTriggerType::EmulatedEdge, Event::FileReadyType::Read);

  state_ = State::kTunneling;
  scheduleIdleTimeout();

  ENVOY_LOG(info, "naive_forward_proxy: UoT tunnel established to {}",
            udp_dest_address_->asString());
}

void NaiveForwardProxyFilter::onFileEvent(uint32_t events) {
  if (events & Event::FileReadyType::Read) {
    onUdpReadable();
  }
}

void NaiveForwardProxyFilter::onUdpReadable() {
  if (udp_fd_ < 0) return;

  auto& os_syscalls = Api::OsSysCallsSingleton::get();
  uint8_t buf[kUdpRecvBufSize];

  while (true) {
    sockaddr_storage peer_addr;
    // OsSysCalls has no recvfrom(); use recvmsg() to also capture the peer
    // address (needed for the isConnect=false UoT source-address encoding).
    iovec iov;
    iov.iov_base = buf;
    iov.iov_len = kUdpRecvBufSize;
    msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &peer_addr;
    msg.msg_namelen = sizeof(peer_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    auto recv_result = os_syscalls.recvmsg(udp_fd_, &msg, 0);

    if (recv_result.return_value_ <= 0) {
      if (recv_result.errno_ != EAGAIN && recv_result.errno_ != EWOULDBLOCK) {
        ENVOY_LOG(warn, "naive_forward_proxy: UDP recv error: {}", recv_result.errno_);
      }
      break;
    }

    int datagram_len = recv_result.return_value_;

    // The UoT length field is a uint16 (max 65535). A datagram larger than that
    // cannot be represented; casting would truncate the length while sending
    // the full payload, desyncing the client's parser. Drop such datagrams
    // (standard UDP payloads never exceed 65507, so this only guards the edge).
    if (datagram_len > 65535) {
      ENVOY_LOG(warn, "naive_forward_proxy: oversized UDP datagram ({}B), dropping",
                datagram_len);
      continue;
    }

    // Encode as UoT data frame
    std::string uot_frame;
    if (udp_is_connect_) {
      uot_frame = encodeDataFrame(
          static_cast<uint16_t>(datagram_len),
          std::string_view(reinterpret_cast<const char*>(buf), datagram_len));
    } else {
      // isConnect=false: include source address
      // Parse peer address
      HostPort src;
      if (peer_addr.ss_family == AF_INET) {
        auto* sin = reinterpret_cast<sockaddr_in*>(&peer_addr);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        src.host = ip;
        src.port = ntohs(sin->sin_port);
      } else {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&peer_addr);
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        src.host = ip;
        src.port = ntohs(sin6->sin6_port);
      }
      uot_frame = encodeDataFrameWithAddr(
          src, static_cast<uint16_t>(datagram_len),
          std::string_view(reinterpret_cast<const char*>(buf), datagram_len));
    }

    // Add padding
    if (padding_enabled_ && padding_encoder_.encodePaddingActive()) {
      uot_frame = padding_encoder_.encode(uot_frame, randomPaddingSize());
    }

    // Send to client
    Buffer::OwnedImpl out_buf;
    out_buf.add(uot_frame.data(), uot_frame.size());
    decoder_callbacks_->encodeData(out_buf, false);
  }
}

void NaiveForwardProxyFilter::relayUotFrameToUdp(const UotFrame& frame) {
  if (udp_fd_ < 0) return;

  auto& os_syscalls = Api::OsSysCallsSingleton::get();
  const auto& payload = frame.payload;

  if (udp_is_connect_) {
    // Connected socket: just send. OsSysCalls::send takes a non-const void*.
    auto send_result = os_syscalls.send(
        udp_fd_, const_cast<char*>(payload.data()), payload.size(), 0);
    if (send_result.return_value_ < 0) {
      ENVOY_LOG(warn, "naive_forward_proxy: UDP send error: {}", send_result.errno_);
    }
  } else {
    // Unconnected socket: send to frame's destination. OsSysCalls has no
    // sendto(); use sendmsg() with msg_name set to the destination sockaddr.
    auto address = Network::Utility::parseInternetAddressNoThrow(
        frame.destination.host, frame.destination.port);
    if (!address) {
      ENVOY_LOG(warn, "naive_forward_proxy: invalid UDP dest: {}:{}",
                frame.destination.host, frame.destination.port);
      return;
    }
    iovec iov;
    iov.iov_base = const_cast<char*>(payload.data());
    iov.iov_len = payload.size();
    msghdr msg;
    memset(&msg, 0, sizeof(msg));
    // sockAddr() returns a const sockaddr*; msg_name is void* (kernel does not
    // modify it on send), so the const_cast is safe here.
    msg.msg_name = const_cast<sockaddr*>(address->sockAddr());
    msg.msg_namelen = address->sockAddrLen();
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    auto send_result = os_syscalls.sendmsg(udp_fd_, &msg, 0);
    if (send_result.return_value_ < 0) {
      ENVOY_LOG(warn, "naive_forward_proxy: UDP sendmsg error: {}", send_result.errno_);
    }
  }
}

// ---- Padding helpers ----

std::string NaiveForwardProxyFilter::addPadding(std::string_view payload) {
  if (!padding_enabled_ || !padding_encoder_.encodePaddingActive()) {
    return std::string(payload);
  }
  return padding_encoder_.encode(payload, randomPaddingSize());
}

uint8_t NaiveForwardProxyFilter::randomPaddingSize() const {
  if (config_->maxPaddingSize() == 0) return 0;
  static thread_local std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<int> dist(0, config_->maxPaddingSize());
  return static_cast<uint8_t>(dist(rng));
}

// ---- Common ----

void NaiveForwardProxyFilter::closeAll() {
  state_ = State::kClosed;

  // Mark this filter dead so any callback from the deferred-deleted upstream
  // connection (TcpReadFilter::onData) that fires after we are gone is a no-op.
  if (alive_) {
    *alive_ = false;
  }

  // Cancel DNS
  if (dns_query_) {
    dns_query_->cancel(Network::ActiveDnsQuery::CancelReason::QueryAbandoned);
    dns_query_ = nullptr;
  }

  // Close TCP upstream.
  //
  // closeAll() is frequently reached from *within* an upstream callback: the
  // TcpReadFilter's onData() calls relayTcpUpstreamToClient() -> encodeData()
  // with end_stream, which resets the downstream stream, destroys this filter
  // (onDestroy/~dtor) and re-enters closeAll(). Destroying tcp_upstream_
  // synchronously here would free the connection (and the TcpReadFilter that
  // owns a reference back to us) while the connection's read path is still on
  // the stack. When control unwinds, the connection code touches its freed
  // read filter -> "pure virtual function called" abort.
  //
  // Fix, mirroring TcpProxy: detach our ConnectionCallbacks so close() cannot
  // re-enter onEvent(), then hand the connection to deferredDelete() so its
  // actual destruction happens after the current call stack fully unwinds.
  if (tcp_upstream_) {
    tcp_upstream_->removeConnectionCallbacks(*this);
    tcp_upstream_->close(Network::ConnectionCloseType::NoFlush);
    dispatcher().deferredDelete(std::move(tcp_upstream_));
    tcp_upstream_ = nullptr;
  }

  // Close UDP socket
  if (udp_file_event_) {
    udp_file_event_.reset();
  }
  if (udp_fd_ >= 0) {
    Api::OsSysCallsSingleton::get().close(udp_fd_);
    udp_fd_ = -1;
  }

  // Cancel idle timer
  if (idle_timer_) {
    idle_timer_->disableTimer();
    idle_timer_.reset();
  }
}

void NaiveForwardProxyFilter::scheduleIdleTimeout() {
  if (!idle_timer_) {
    idle_timer_ = dispatcher().createTimer([this]() {
      ENVOY_LOG(info, "naive_forward_proxy: idle timeout, closing tunnel");
      closeAll();
      decoder_callbacks_->resetStream(Http::StreamResetReason::ConnectionTimeout,
                                      "Idle timeout");
    });
  }
  idle_timer_->enableTimer(config_->idleTimeout());
}

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
