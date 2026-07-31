load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load("//test/extensions:extensions_build_system.bzl", "envoy_extension_cc_test")

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "disguise_cert_test",
    srcs = ["disguise_cert_test.cc"],
    extension_names = ["envoy.tls_handshakers.reality"],
    external_deps = ["ssl"],
    deps = [
        "//source/extensions/transport_sockets/reality:reality",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/extensions/transport_sockets/reality/v3:pkg_cc_proto",
    ],
)
