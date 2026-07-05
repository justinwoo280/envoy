load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_extension(
    name = "reality",
    srcs = [
        "config.cc",
        "mirror_dialer.cc",
        "reality_config.cc",
        "reality_handshaker.cc",
    ],
    hdrs = [
        "mirror_dialer.h",
        "reality_config.h",
        "reality_handshaker.h",
    ],
    deps = [
        "//envoy/api:api_interface",
        "//envoy/event:dispatcher_interface",
        "//envoy/network:dns_interface",
        "//envoy/registry",
        "//envoy/ssl:handshaker_interface",
        "//source/common/api:os_sys_calls_lib",
        "//source/common/common:utility_lib",
        "//source/common/network:address_lib",
        "//source/common/network:utility_lib",
        "//source/common/network/dns_resolver:dns_factory_util_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/tls:ssl_handshaker_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/transport_sockets/reality/v3:pkg_cc_proto",
    ],
)
