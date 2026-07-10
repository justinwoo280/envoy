load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

# L4 REALITY authenticator: peeks the ClientHello, runs REALITY auth, and writes
# the verdict into dynamic metadata so a filter_chain_matcher can route
# authenticated connections to the REALITY TLS chain and unauthenticated ones
# (probers) to a transparent tcp_proxy fallback to the real dest.

envoy_extension_package()

envoy_cc_library(
    name = "reality_authenticator_lib",
    srcs = ["reality_authenticator.cc"],
    hdrs = ["reality_authenticator.h"],
    external_deps = ["ssl"],
    deps = [
        "//envoy/buffer:buffer_interface",
        "//envoy/common:exception_lib",
        "//envoy/network:filter_interface",
        "//envoy/network:listen_socket_interface",
        "//envoy/stream_info:filter_state_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:hex_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/common/protobuf",
        "//source/common/router:string_accessor_lib",
        "//source/extensions/transport_sockets/reality:reality_auth_lib",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
        "@envoy_api//envoy/extensions/filters/listener/reality_authenticator/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    deps = [
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//source/extensions/filters/listener/reality_authenticator:reality_authenticator_lib",
        "@envoy_api//envoy/extensions/filters/listener/reality_authenticator/v3:pkg_cc_proto",
    ],
)
