#include <string>

#include "envoy/extensions/filters/listener/reality_authenticator/v3/reality_authenticator.pb.h"
#include "envoy/extensions/filters/listener/reality_authenticator/v3/reality_authenticator.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/listener/reality_authenticator/reality_authenticator.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace RealityAuthenticator {

// Config registration for the REALITY authenticator listener filter.
class RealityAuthenticatorConfigFactory
    : public Server::Configuration::NamedListenerFilterConfigFactory {
public:
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message& message,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      Server::Configuration::ListenerFactoryContext& context) override {
    const auto& proto_config = MessageUtil::downcastAndValidate<
        const envoy::extensions::filters::listener::reality_authenticator::v3::RealityAuthenticator&>(
        message, context.messageValidationVisitor());

    ConfigSharedPtr config = std::make_shared<Config>(proto_config);
    return
        [listener_filter_matcher, config](Network::ListenerFilterManager& filter_manager) -> void {
          filter_manager.addAcceptFilter(listener_filter_matcher, std::make_unique<Filter>(config));
        };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<
        envoy::extensions::filters::listener::reality_authenticator::v3::RealityAuthenticator>();
  }

  std::string name() const override { return "envoy.filters.listener.reality_authenticator"; }
};

REGISTER_FACTORY(RealityAuthenticatorConfigFactory,
                 Server::Configuration::NamedListenerFilterConfigFactory);

} // namespace RealityAuthenticator
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
