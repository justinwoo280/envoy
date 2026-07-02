# Envoy 裁剪方案（naive_forward_proxy + REALITY 服务端）

目标：**最小化最终二进制体积**。手段：`extensions_build_config.bzl` 白名单 + 编译开关 +
strip。定位：通用 naive_forward_proxy 服务端，REALITY 为可选 TLS 层开关。

> 环境当前无 Bazel/Java，**本方案未经编译验证**。所有标注 ⚠️RISK 的项必须在有
> Bazel 环境时逐一验证（砍一批→编译→看缺失符号→回加）。

## 数据路径（决定必留集）

下游: TLS listener → tls_inspector → HCM(h2) → naive_forward_proxy filter
上游: filter **自建** DNS 解析 + **自建** TCP client connection（不走 cluster/router 上游）
REALITY: tls_handshakers.reality 替换下游 TLS 握手
配置: 静态文件（filesystem），无 xDS

关键事实（已从源码确认）：
- naive filter 对 CONNECT 返回 StopIteration，**请求不进 router**；自己 encodeHeaders/
  encodeData 回注、自己 `createDnsResolver` + 建 `tcp_upstream_`。
- 因此 cluster / load_balancing / upstream / router 在纯 naive 路径**可能非必需**，但
  HCM 配置校验与非-CONNECT fallback 可能仍要求 route/cluster。⚠️RISK

## 必留白名单（保守，先保证能跑）

### 网络/HTTP 骨架
- envoy.filters.network.http_connection_manager   ← 核心
- envoy.filters.network.tcp_proxy                 ← 可能被 HCM/监听器依赖，先留 ⚠️
- envoy.filters.http.router                       ← 先留（HCM 常要求）⚠️RISK 可试砍
- envoy.filters.http.naive_forward_proxy          ← 你的
- envoy.filters.listener.tls_inspector            ← REALITY/TLS 监听需要
- envoy.filters.listener.http_inspector           ← h1/h2 探测，先留 ⚠️ 可试砍
- envoy.filters.listener.original_dst             ← 透明代理才需要，可砍（除非用到）

### transport sockets / TLS
- envoy.transport_sockets.tls                     ← 下游 TLS
- envoy.transport_sockets.raw_buffer              ← 上游明文隧道
- envoy.tls_handshakers.reality                   ← 你的
- envoy.tls.cert_validator.spiffe                 ← ⚠️ 可能非必需，可试砍
- envoy.http.header_validators.envoy_default      ← HCM h2 header 校验，必留

### DNS（naive filter 自建解析必需）
- envoy.network.dns_resolver.cares                ← 保留一个即可（c-ares）
  （getaddrinfo 更小但功能少；apple 仅 mac；hickory 是 rust。二选一，见风险）

### 集群/上游（若 router 保留则必需）
- envoy.clusters.static
- envoy.clusters.strict_dns / logical_dns         ← 视配置
- envoy.upstreams.http.http / tcp
- envoy.load_balancing_policies.round_robin       ← 至少留一个 LB
- 以上整组 ⚠️RISK：若确认 router 可砍则可一并砍

### 运行必需的杂项（core 常隐式依赖）
- envoy.access_loggers.file / stdout / stderr     ← 至少留 file
- envoy.request_id.uuid                            ← HCM 默认依赖
- envoy.config_subscription.filesystem            ← 静态配置
- envoy.config_mux.*（如 core 依赖）              ⚠️
- envoy.regex_engines.* / string_matcher（core）  ⚠️
- envoy.matching.* 里被 core 依赖的最小子集        ⚠️RISK（matching 常被 HCM 路由依赖）
- envoy.formatter.*（access log 格式）保留最小

## 可全砍的大类（与 naive 服务端无关）

| 类 | 数量 | 说明 |
|---|---|---|
| tracers.* | 15 | 追踪，全砍 |
| wasm（filters/network/http/bootstrap/access_loggers/stat_sinks.wasm） | ~6 | **V8 大头**，全砍，省体积+编译时间最多 |
| dynamic_modules（各类里的 *.dynamic_modules） | ~10 | 全砍 |
| stat_sinks.*（statsd/datadog/graphite/hystrix/otel/metrics_service） | 8 | 全砍 |
| filters.network 里的协议代理：dubbo/mongo/redis/thrift/zookeeper/generic_proxy | ~7 | 全砍 |
| filters.network 其他：ext_authz/ext_proc/ratelimit/rbac/geoip/reverse_tunnel/set_filter_state/sni_*/echo/direct_response/connection_limit/tcp_bandwidth_limit/local_ratelimit | ~15 | 全砍 |
| filters.http 绝大部分（保留见白名单，其余 ~65 个全砍）：lua/jwt_authn/oauth2/ext_authz/ext_proc/grpc_*/cache*/compressor/decompressor/fault/tap/rbac/cors/csrf/wasm/aws_*/mcp*/a2a/gcp_authn/... | ~65 | 全砍 |
| filters.udp.* | 5 | naive 用 CONNECT+自建 UDP，不走 udp_proxy，全砍 ⚠️ 确认 UoT 不依赖 |
| clusters 里 redis/dynamic_forward_proxy/aggregate/eds/original_dst/reverse_connection/mcp/composite/dns | ~9 | 全砍（保留 static/strict_dns/logical_dns）|
| health_checkers.* | 5 | 全砍（除非配了主动健康检查）|
| compression.*（brotli/gzip/zstd） | 6 | 全砍（naive 不做内容压缩）⚠️ 确认 h2 不强依赖 |
| transport_sockets 里 alts/tap/tcp_stats/starttls/internal_upstream/http_11_proxy/upstream_proxy_protocol | ~7 | 全砍（保留 tls/raw_buffer）|
| access_loggers 里 grpc/otel/fluentd/wasm/tcp_grpc/stats/extension_filters | ~8 | 全砍（保留 file/stdout/stderr）|
| config_subscription 里 ads/grpc/rest/delta_grpc/collection 系列 | ~8 | 全砍（保留 filesystem，纯静态配置）|
| quic.* | 9 | 若不用 HTTP/3 全砍 ⚠️（naive 用 h2 over TLS，不需要 QUIC）|
| formatter 里 cel/dynamic_modules | 少量 | 砍非必需 |
| retry_*/internal_redirect_*/path/rbac/stateful_session/custom_response/injected_credentials/original_ip_detection 等 | 多 | 全砍 |
| resource_monitors 大部分、watchdog.profile_action | 少量 | 砍非必需 |
| load_balancing 里除 round_robin 外 | ~11 | 全砍 |

## 编译开关（bazel --define / config）

```
--define=wasm=disabled          # 关 V8，体积+编译时间最大收益
--define=hot_restart=disabled
--define=admin_html=disabled
--define=admin_functionality=disabled   # 若不需要 admin，⚠️ 有些运维依赖
--define=signal_trace=disabled
--define=deprecated_features=disabled
```
opt + strip:
```
bazel build -c opt --config=clang \
  --define=wasm=disabled \
  //source/exe:envoy-static
strip -s bazel-bin/source/exe/envoy-static -o envoy-min
```

## 预期收益（粗估，非实测）

- 关 WASM/V8：编译时间与体积**最大单项**收益（V8 极重）。
- 砍 ~250 个扩展 + strip：最终二进制从 default ~100MB+ 量级降到 **~30-60MB**。
- 无法到 naiveproxy 的 3MB：Envoy core + BoringSSL + protobuf + abseil + c-ares 基础盘就几十 M。

## 高风险点（必须编译验证）

1. ⚠️ **router 能否砍**：naive 走 StopIteration 不进 router，但 HCM 配置/非 CONNECT
   fallback 可能要求。先保留，确认可砍再砍。
2. ⚠️ **matching.* 最小子集**：HCM 路由匹配可能隐式依赖若干 matcher input/matcher。
   砍多了会在配置加载时报 "didn't find a registered factory"。
3. ⚠️ **cluster/upstream/LB**：若 router 砍掉，这组可一并砍；否则至少留 static+round_robin。
4. ⚠️ **quic**：确认部署确实不用 HTTP/3。naive 是 h2-over-TLS，正常不需要。
5. ⚠️ **compression**：确认 h2 传输不强依赖（内容压缩是 filter，传输层 h2 不需要）。
6. ⚠️ **udp filters**：确认 UoT 的 UDP 路径是 filter 自建 socket，不依赖 udp_proxy。
   （已从源码看到 filter 自建 os_syscalls socket，大概率可砍，仍需验证）
7. ⚠️ **config_mux / config_subscription**：纯静态配置只需 filesystem，但 core 启动
   可能仍注册 mux 工厂。砍后若启动报错则回加。

## 建议的迭代顺序（有 Bazel 后）

1. 第一刀（低风险）：tracers + wasm + dynamic_modules + 协议代理(redis/mongo/dubbo/
   thrift/zk/kafka) + stat_sinks + 明显无关 http filters(~50个)。编译。
2. 第二刀（中风险）：compression + health_checkers + 大部分 transport_sockets +
   access_loggers(留file) + config_subscription(留filesystem) + quic。编译。
3. 第三刀（高风险）：尝试砍 router/cluster/upstream/LB，砍 matching 到最小。编译，
   **并用真实 naive + REALITY 配置做端到端冒烟测试**（不只是编译通过）。
4. strip + 体积对比，记录每刀的收益。
