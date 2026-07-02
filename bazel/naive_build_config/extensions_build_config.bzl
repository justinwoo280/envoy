# Minimal extension allowlist for the NaiveProxy-REALITY server build.
#
# This file REPLACES source/extensions/extensions_build_config.bzl at build
# time via a `envoy_build_config` repository override registered in WORKSPACE
# (see bazel/naive_build_config/README before envoy_dependencies()). The
# canonical file is left untouched.
#
# Strategy: start from the smallest set that boots a full downstream-TLS ->
# tls_inspector -> HCM(h2) -> naive_forward_proxy data path with the REALITY
# handshaker, then trim further per NAIVE_TRIM.md ("砍一批->编译->回加").
#
# Every label below was verified to exist in the upstream
# source/extensions/extensions_build_config.bzl. Keys are the canonical
# extension names; a wrong label makes Bazel fail with "no such target".
#
# NOTE: envoy.request_id.uuid is intentionally absent — HCM depends on it
# directly (source/extensions/filters/network/http_connection_manager/BUILD),
# not through this allowlist.

EXTENSIONS = {
    #
    # Network / HTTP skeleton
    #
    "envoy.filters.network.http_connection_manager": "//source/extensions/filters/network/http_connection_manager:config",
    "envoy.filters.network.tcp_proxy": "//source/extensions/filters/network/tcp_proxy:config",
    "envoy.filters.http.router": "//source/extensions/filters/http/router:config",
    # The naive forward proxy filter (this project).
    "envoy.filters.http.naive_forward_proxy": "//source/extensions/filters/http/naive_forward_proxy:config",

    #
    # Listener filters (TLS/h2 detection for REALITY)
    #
    "envoy.filters.listener.tls_inspector": "//source/extensions/filters/listener/tls_inspector:config",
    "envoy.filters.listener.http_inspector": "//source/extensions/filters/listener/http_inspector:config",

    #
    # Transport sockets / TLS
    #
    "envoy.transport_sockets.tls": "//source/extensions/transport_sockets/tls:config",
    "envoy.transport_sockets.raw_buffer": "//source/extensions/transport_sockets/raw_buffer:config",
    # The REALITY custom TLS handshaker (this project).
    "envoy.tls_handshakers.reality": "//source/extensions/transport_sockets/reality:reality",

    #
    # DNS (naive filter builds its own resolver)
    #
    "envoy.network.dns_resolver.cares": "//source/extensions/network/dns_resolver/cares:config",
    "envoy.network.dns_resolver.getaddrinfo": "//source/extensions/network/dns_resolver/getaddrinfo:config",

    #
    # Clusters / upstreams / LB (required while router is kept)
    #
    "envoy.clusters.static": "//source/extensions/clusters/static:static_cluster_lib",
    "envoy.upstreams.http.http": "//source/extensions/upstreams/http/http:config",
    "envoy.upstreams.http.tcp": "//source/extensions/upstreams/http/tcp:config",
    "envoy.load_balancing_policies.round_robin": "//source/extensions/load_balancing_policies/round_robin:config",
    "envoy.load_balancing_policies.cluster_provided": "//source/extensions/load_balancing_policies/cluster_provided:config",

    #
    # HTTP header validation (HCM h2 requires this)
    #
    "envoy.http.header_validators.envoy_default": "//source/extensions/http/header_validators/envoy_default:config",

    #
    # Access logging (keep file + stream for smoke tests)
    #
    "envoy.access_loggers.file": "//source/extensions/access_loggers/file:config",
    "envoy.access_loggers.stdout": "//source/extensions/access_loggers/stream:config",
    "envoy.access_loggers.stderr": "//source/extensions/access_loggers/stream:config",

    #
    # Config subscription (static filesystem config only, no xDS)
    #
    "envoy.config_subscription.filesystem": "//source/extensions/config_subscription/filesystem:filesystem_subscription_lib",
}

WINDOWS_EXTENSIONS = {}

# Match the canonical extensions_build_config.bzl visibility values exactly.
EXTENSION_CONFIG_VISIBILITY = ["//:extension_config", "//:contrib_library", "//:mobile_library"]
EXTENSION_PACKAGE_VISIBILITY = ["//:extension_library", "//:contrib_library", "//:mobile_library"]
CONTRIB_EXTENSION_PACKAGE_VISIBILITY = ["//:contrib_library"]
MOBILE_PACKAGE_VISIBILITY = ["//:mobile_library"]

LEGACY_ALWAYSLINK = 1
