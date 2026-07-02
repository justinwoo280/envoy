#pragma once

#include "envoy/extensions/filters/http/naive_forward_proxy/v3/naive_forward_proxy.pb.h"
#include "envoy/extensions/filters/http/naive_forward_proxy/v3/naive_forward_proxy.pb.validate.h"
#include "envoy/http/filter.h"
#include "envoy/server/factory_context.h"

#include "source/extensions/filters/http/common/factory_base.h"
#include "source/extensions/filters/http/naive_forward_proxy/naive_forward_proxy.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace NaiveForwardProxy {

class NaiveForwardProxyFactory
    : public Common::FactoryBase<
          envoy::extensions::filters::http::naive_forward_proxy::v3::NaiveForwardProxy> {
public:
  NaiveForwardProxyFactory() : FactoryBase("envoy.filters.http.naive_forward_proxy") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::naive_forward_proxy::v3::NaiveForwardProxy&
          proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;

  LinkMode mode() const override { return LinkMode::Strict; }
};

} // namespace NaiveForwardProxy
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
