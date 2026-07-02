load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "uot_framer_lib",
    srcs = ["uot_framer.cc"],
    hdrs = ["uot_framer.h"],
    deps = [
        "//envoy/common:base_includes",
        "//source/common/common:byte_order_lib",
    ],
)

envoy_cc_library(
    name = "naive_padding_framer_lib",
    srcs = ["naive_padding_framer.cc"],
    hdrs = ["naive_padding_framer.h"],
)

envoy_cc_library(
    name = "naive_forward_proxy_lib",
    srcs = ["naive_forward_proxy.cc"],
    hdrs = ["naive_forward_proxy.h"],
    deps = [
        ":naive_padding_framer_lib",
        ":uot_framer_lib",
        "//envoy/event:dispatcher_interface",
        "//envoy/event:file_event_interface",
        "//envoy/http:filter_interface",
        "//envoy/network:connection_interface",
        "//envoy/network:dns_interface",
        "//source/common/api:os_sys_calls_lib",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:utility_lib",
        "//source/common/http:header_utility_lib",
        "//source/common/http:headers_lib",
        "//source/common/network:address_lib",
        "//source/common/network:socket_lib",
        "//source/common/network:utility_lib",
        "//source/extensions/filters/http/common:pass_through_filter_lib",
        "@envoy_api//envoy/extensions/filters/http/naive_forward_proxy/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    deps = [
        ":naive_forward_proxy_lib",
        "//envoy/registry",
        "//envoy/server:filter_config_interface",
        "//source/extensions/filters/http/common:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/http/naive_forward_proxy/v3:pkg_cc_proto",
    ],
)
