workspace(name = "envoy")

load("//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

# NaiveProxy-REALITY minimal server build: register our extension allowlist as
# @envoy_build_config BEFORE envoy_dependencies(), which only falls back to the
# full default allowlist when this repo is not already defined
# (bazel/repositories.bzl:151). Canonical extensions_build_config.bzl untouched.
new_local_repository(
    name = "envoy_build_config",
    path = "bazel/naive_build_config",
    build_file_content = "",
)

load("//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("//bazel:bazel_deps.bzl", "envoy_bazel_dependencies")

envoy_bazel_dependencies()

load("//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("//bazel:python_dependencies.bzl", "envoy_python_dependencies")

envoy_python_dependencies()

load("//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

load("//bazel:repo.bzl", "envoy_repo")

envoy_repo()

load("//bazel:toolchains.bzl", "envoy_toolchains")

envoy_toolchains()

load("//bazel:dependency_imports_extra.bzl", "envoy_dependency_imports_extra")

envoy_dependency_imports_extra()
