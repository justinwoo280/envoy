#!/usr/bin/env bash
# Runs INSIDE the official envoy-build container (invoked as the single
# DOCKER_COMMAND by ci/run_envoy_docker.sh). It must be a single-word command
# because that wrapper's entrypoint runs `exec $DOCKER_COMMAND` unquoted; a
# multi-word inline command would be word-split and its `&&` chain lost.
#
# Builds the minimal naive+REALITY envoy-static, strips it to /build/envoy-min
# (mounted to the host at ${ENVOY_DOCKER_BUILD_DIR:-/tmp/envoy-docker-build}),
# from where the host job copies it out.
set -euxo pipefail

COMPILE_MODE="${COMPILE_MODE:-opt}"

bazel build \
  --config=clang \
  --disk_cache=/build/bazel-disk \
  --repository_cache=/build/bazel-repo \
  --jobs=4 \
  --local_ram_resources=13000 \
  --define=wasm=disabled \
  --define=hot_restart=disabled \
  --define=admin_html=disabled \
  --define=signal_trace=disabled \
  --define=deprecated_features=disabled \
  -c "${COMPILE_MODE}" \
  //source/exe:envoy-static

strip -s bazel-bin/source/exe/envoy-static -o /build/envoy-min
# Also keep an UNSTRIPPED copy for symbolized crash backtraces (diagnostics).
cp bazel-bin/source/exe/envoy-static /build/envoy-unstripped || true
/build/envoy-min --version
ls -lh /build/envoy-min
ls -lh /build/envoy-unstripped || true
