#include <memory>

#include "envoy/extensions/transport_sockets/reality/v3/reality.pb.h"
#include "envoy/extensions/transport_sockets/reality/v3/reality.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/ssl/handshaker.h"

#include "source/common/common/utility.h"
#include "source/common/protobuf/utility.h"
#include "source/common/tls/ssl_handshaker.h"
#include "source/extensions/transport_sockets/reality/reality_config.h"
#include "source/extensions/transport_sockets/reality/reality_handshaker.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Reality {

class RealityHandshakerFactory : public Ssl::HandshakerFactory {
public:
  std::string name() const override { return "envoy.tls_handshakers.reality"; }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<
        envoy::extensions::transport_sockets::reality::v3::RealityConfig>();
  }

  Ssl::HandshakerFactoryCb
  createHandshakerCb(const Protobuf::Message& config,
                     Ssl::HandshakerFactoryContext& /*context*/,
                     ProtobufMessage::ValidationVisitor& validation_visitor) override {
    const auto& proto = MessageUtil::downcastAndValidate<
        const envoy::extensions::transport_sockets::reality::v3::RealityConfig&>(
        config, validation_visitor);

    auto reality_config = std::make_shared<RealityConfig>(proto);

    return [reality_config](bssl::UniquePtr<SSL> ssl, int ssl_extended_socket_info_index,
                            Ssl::HandshakeCallbacks* handshake_callbacks)
               -> Ssl::HandshakerSharedPtr {
      return std::make_shared<RealityHandshaker>(
          std::move(ssl), ssl_extended_socket_info_index, handshake_callbacks, reality_config);
    };
  }

  Ssl::HandshakerCapabilities capabilities() const override {
    Ssl::HandshakerCapabilities caps;
    caps.provides_certificates = true;
    caps.provides_ciphers_and_curves = true;
    caps.provides_sigalgs = true;
    return caps;
  }

  Ssl::SslCtxCb sslctxCb(Ssl::HandshakerFactoryContext& /*context*/) const override {
    return [](SSL_CTX* ctx) {
      // TLS 1.3 only
      SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
      SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

      // Allow both plain X25519 and the post-quantum hybrid X25519MLKEM768.
      // REALITY authenticates using only the X25519 component of whichever the
      // client offers, and our BoringSSL patch replaces the mirror ServerHello
      // key_share group-agnostically (by length). IMPORTANT: the negotiated
      // group MUST match the group in the captured mirror_server_hello, since
      // reality_replace_key_share requires equal key_share lengths. Operators
      // must capture the mirror ServerHello from the real target using the same
      // group the clients will negotiate (modern clients default to
      // X25519MLKEM768). If your mirror capture is plain X25519, restrict this
      // to "X25519" instead.
      SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519");

      // Set select_certificate_cb for REALITY auth extraction
      SSL_CTX_set_select_certificate_cb(ctx, RealityHandshaker::selectCertCb_);

      // Set the REALITY ServerHello mirror callback (BoringSSL patch)
      SSL_set_reality_serverhello_cb(RealityHandshaker::realityServerHelloCb_);
    };
  }
};

REGISTER_FACTORY(RealityHandshakerFactory, Ssl::HandshakerFactory);

} // namespace Reality
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
