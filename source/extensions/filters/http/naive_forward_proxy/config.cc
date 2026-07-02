#include "source/extensions/filters/http/naive_forward_proxy/config.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

Http::FilterFactoryCb NaiveForwardProxyFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::naive_forward_proxy::v3::NaiveForwardProxy&
        proto_config,
    const std::string&, Server::Configuration::FactoryContext& context) {
  auto config = std::make_shared<Config>(proto_config, context);
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<NaiveForwardProxyFilter>(config));
  };
}

// Register the filter
REGISTER_FACTORY(NaiveForwardProxyFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
