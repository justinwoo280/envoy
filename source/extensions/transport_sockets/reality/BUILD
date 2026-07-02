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
        "reality_config.cc",
        "reality_handshaker.cc",
    ],
    hdrs = [
        "reality_config.h",
        "reality_handshaker.h",
    ],
    deps = [
        "//envoy/registry",
        "//envoy/ssl:handshaker_interface",
        "//source/common/common:utility_lib",
        "//source/common/protobuf:utility_lib",
        "//source/common/tls:ssl_handshaker_lib",
        "@envoy_api//envoy/extensions/transport_sockets/reality/v3:pkg_cc_proto",
    ],
)
