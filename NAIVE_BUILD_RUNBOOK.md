# NaiveProxy-REALITY Envoy server — build runbook

Companion to `NAIVE_TRIM.md` (the trim *design*). This is the *executable*
procedure to produce a minimal `envoy-min` server binary for end-to-end
traffic testing, on a dedicated build machine.

## What was fixed / added in-repo

| Item | Path | Why |
|------|------|-----|
| Missing proto package | `api/envoy/extensions/filters/http/naive_forward_proxy/v3/{naive_forward_proxy.proto,BUILD}` | The naive filter BUILD referenced `@envoy_api//.../naive_forward_proxy/v3:pkg_cc_proto`, which did not exist. Without it the Bazel build **fails immediately**. Fields match `Config::Config()` reads exactly. |
| Minimal extension allowlist | `bazel/naive_build_config/extensions_build_config.bzl` | ~20 extensions instead of ~328. Every label verified against the canonical file. |
| Allowlist override | `WORKSPACE` (block before `envoy_dependencies()`) + `bazel/naive_build_config/{BUILD.bazel,WORKSPACE.snippet}` | Registers `@envoy_build_config` first so Envoy uses our allowlist. Canonical `source/extensions/extensions_build_config.bzl` is **untouched**. |
| Build script | `build_naive_server.sh` | opt+strip, wasm disabled, RAM/jobs caps to avoid OOM. |

The REALITY BoringSSL server patch was already wired at
`bazel/repositories.bzl:285` (`bazel/boringssl-reality.patch`) — no change needed.

## Build machine resource requirements

Envoy from a cold cache pulls & compiles BoringSSL, protobuf, abseil, c-ares,
re2, quiche, etc. Plan for:

| Resource | Minimum | Comfortable |
|----------|---------|-------------|
| CPU | 8 cores | 16-32 cores |
| RAM | **~4 GB per parallel job** at link time | 32-64 GB |
| Swap | strongly recommended if RAM is tight (no swap = hard OOM kills) | — |
| Disk | ~25 GB (bazel cache + outputs) | 40+ GB |
| Time (cold) | ~1.5-3 h even trimmed; V8 already excluded via `wasm=disabled` | — |

`build_naive_server.sh` auto-caps `--jobs` at `RAM_MB / 3500` and sets
`--local_ram_resources`. On a swap-less box, if a link action still OOMs,
lower jobs: `JOBS=6 ./build_naive_server.sh`.

> This current box (16 core / 31 GB / **no swap**) can technically build it but
> is at OOM risk near link time and would take multiple hours. Use the
> dedicated build machine you mentioned.

## Procedure

```bash
# 0. On the build machine, install bazelisk (honors .bazelversion = 8.7.0)
#    OR use the Docker path: ./ci/run_envoy_docker.sh 'bash build_naive_server.sh'

# 1. Smoke/fast build first (faster, catches allowlist/proto errors early)
DBG=1 ./build_naive_server.sh

# 2. Validate the binary loads a real config WITHOUT serving traffic
./envoy-min --mode validate -c naive_reality_smoke.yaml

# 3. If validate passes, do the real optimized+stripped build
./build_naive_server.sh          # -> ./envoy-min (stripped)
```

## Staged trimming (do AFTER the above succeeds)

The allowlist in `bazel/naive_build_config/extensions_build_config.bzl` is
deliberately conservative (keeps router/cluster/LB/http_inspector). Once a full
build + smoke test passes, trim further and re-verify, per `NAIVE_TRIM.md`:

1. Try removing `http_inspector`, then one of the two DNS resolvers
   (keep `cares` OR `getaddrinfo`). Rebuild + `--mode validate`.
2. Try removing `router` + `clusters.static` + `upstreams.http.*` + LB
   (the naive filter self-builds upstreams and returns StopIteration, so router
   *may* be unnecessary — but HCM config validation may still require it).
   Rebuild + **live** smoke test, not just validate.
3. Each removal: if you see `Didn't find a registered implementation for ...`
   at config load, add that extension back.

## Smoke-test config

A minimal `naive_reality_smoke.yaml` skeleton lives next to this file. Fill in:
- `private_key` (raw 32-byte X25519, base64) — pairs with the client's public key
- `short_id` — must match client
- `mirror_server_hello` — captured ServerHello bytes from the mirror target
- `username`/`password` — client Basic auth

Type URLs used:
- filter: `type.googleapis.com/envoy.extensions.filters.http.naive_forward_proxy.v3.NaiveForwardProxy`
- handshaker: `type.googleapis.com/envoy.extensions.transport_sockets.reality.v3.RealityConfig`
