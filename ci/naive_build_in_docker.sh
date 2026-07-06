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

# Size bazel to the host. GitHub Actions runners are 4c/16g; CircleCI machine
# xlarge is 8c/32g. Rather than hardcode, detect cores + RAM so the same script
# is fast everywhere without link-time OOM.
#   jobs = min(nproc, floor(RAM_MB / 3500))  -- ~3.5 GB/link-job headroom
#   ram  = RAM_MB - 4000                     -- leave 4 GB for the OS/toolchain
# NAIVE_BAZEL_JOBS / NAIVE_BAZEL_RAM override the detection if set (both are in
# the docker-compose env allowlist path via NUM_CPUS, or can be exported).
CORES="${NUM_CPUS:-$(nproc)}"
RAM_MB="$(awk '/MemTotal/ {printf "%d", $2/1024}' /proc/meminfo)"
RAM_JOB_CAP=$(( RAM_MB / 3500 ))
JOBS="${NAIVE_BAZEL_JOBS:-$(( CORES < RAM_JOB_CAP ? CORES : RAM_JOB_CAP ))}"
[ "${JOBS}" -lt 1 ] && JOBS=1
LOCAL_RAM="${NAIVE_BAZEL_RAM:-$(( RAM_MB > 5000 ? RAM_MB - 4000 : RAM_MB ))}"
echo "naive build sizing: cores=${CORES} ram_mb=${RAM_MB} -> jobs=${JOBS} local_ram=${LOCAL_RAM}"

bazel build \
  --config=clang \
  --disk_cache=/build/bazel-disk \
  --repository_cache=/build/bazel-repo \
  --jobs="${JOBS}" \
  --local_ram_resources="${LOCAL_RAM}" \
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
