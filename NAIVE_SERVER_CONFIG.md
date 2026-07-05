# NaiveProxy-REALITY Envoy server — configuration guide

How to configure the `envoy-min` server. For *building* the binary see
`NAIVE_BUILD_RUNBOOK.md`; for architecture and rationale see `DESIGN.md`.

The server must run on a **remote VPS** — never colocated with the client.

## Minimal working config

```yaml
admin:
  address:
    socket_address: { address: 127.0.0.1, port_value: 9901 }

static_resources:
  listeners:
  - name: reality_listener
    address:
      socket_address: { address: 0.0.0.0, port_value: 8443 }
    listener_filters:
    - name: envoy.filters.listener.tls_inspector
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: naive
          codec_type: HTTP2                      # (1) MUST be HTTP2
          route_config:
            name: local
            virtual_hosts:
            - name: naive
              domains: ["*"]
              routes:
              - match: { connect_matcher: {} }
                route:
                  cluster: dummy                 # (2) dummy STATIC cluster
                  upgrade_configs:
                  - { upgrade_type: CONNECT, connect_config: {} }
          http_filters:
          - name: envoy.filters.http.naive_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.naive_forward_proxy.v3.NaiveForwardProxy
              username: "CHANGE_ME"
              password: "CHANGE_ME"
              fast_open: true                    # (3) see note on fast_open
              max_padding_size: 256
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            alpn_protocols: ["h2"]               # (4) MUST include h2
            custom_handshaker:                   # (5) REALITY handshaker
              name: envoy.tls_handshakers.reality
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.transport_sockets.reality.v3.RealityConfig
                private_key: "<base64 raw 32-byte X25519 private key>"
                short_id: "<base64 short id, matches client>"
                mirror_server_hello: "<base64 ServerHello captured from the mirror>"
                max_time_diff_seconds: 90

  clusters:
  - name: dummy                                  # exists only to satisfy config validation;
    type: STATIC                                 # the filter builds its own upstreams.
    load_assignment:
      cluster_name: dummy
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: 127.0.0.1, port_value: 1 }
```

## The five things you cannot get wrong

1. **`codec_type: HTTP2`.** naive tunnels each proxied connection as an HTTP/2
   stream carrying a `CONNECT`.
2. **A dummy `STATIC` cluster** referenced by the CONNECT route. The
   `naive_forward_proxy` filter opens its own upstream connections and returns
   `StopIteration`, so the cluster is never actually dialed — but HCM/route
   config validation requires a target cluster to exist.
3. **`fast_open`** (optional, default depends on build): when true the server
   sends `200 OK` from `decodeHeaders` (lower latency). The filter buffers any
   client bytes that arrive before the upstream finishes connecting, so this is
   safe (see `DESIGN.md` §5.2 — the fast-open dropped-payload stall is fixed).
4. **`alpn_protocols: ["h2"]`.** Omitting `h2` breaks ALPN and the client cannot
   establish the H2 session. This is the most common "it validates but doesn't
   work" mistake.
5. **`custom_handshaker: envoy.tls_handshakers.reality`** with a valid
   `private_key`, `short_id`, and `mirror_server_hello`.

## REALITY handshaker fields

| Field | Meaning |
|-------|---------|
| `private_key` | Raw 32-byte X25519 private key, base64. Pairs with the client's `public_key`. |
| `short_id` | Base64; must byte-match the client's `short_id`. |
| `mirror_server_hello` | Base64 of a real ServerHello captured from the mirror site (`server_name`). The handshaker replays/derives from it so the client sees the mirror's fingerprint. |
| `max_time_diff_seconds` | Clock-skew tolerance for the REALITY auth timestamp (e.g. 90). |

Notes:
- The handshaker offers groups `X25519MLKEM768:X25519`. REALITY authenticates on
  the X25519 component regardless of whether the client sent plain X25519 or the
  post-quantum hybrid. If your mirror capture is plain X25519, you may restrict
  to `X25519`.
- The injected leaf is an **Ed25519** cert; the handshaker declares
  `provides_sigalgs`, so signing prefs are pinned to `SSL_SIGN_ED25519`
  internally. No config needed, but don't be surprised by Ed25519 in captures.

## Matching client config (naive)

```jsonc
{
  "listen": "socks://127.0.0.1:1080",
  "proxy":  "https://CHANGE_ME:CHANGE_ME@YOUR_VPS_IP:8443",
  "reality": {
    "server_name": "<the mirror host, e.g. www.apple.com>",
    "public_key":  "<base64 X25519 public key, pairs with server private_key>",
    "short_id":    "<base64, matches server>",
    "version":     [1, 0, 0]
  }
  // optional: "no-post-quantum": true  to force plain X25519
  // optional: "bind-interface": "auto" for system-wide TUN mode (see tun/README.md)
}
```

## Validate before serving

```sh
./envoy-min --mode validate -c your_config.yaml   # config load only, no traffic
./envoy-min -c your_config.yaml --concurrency 1 -l warning
```

If config load fails with `Didn't find a registered implementation for '<name>'`,
the binary was trimmed too aggressively — add that extension back per
`NAIVE_TRIM.md`.

## Operational reality

- Put the server on a remote VPS. The client handles its own local bypass
  (bind-interface / TUN hooks); the server does not participate in that.
- Expect the server to be lightly loaded (~10% CPU under concurrent load); the
  naive **client** is the bottleneck (PQC handshake pins a core).
- The server survives concurrent load with zero crashes and zero stalls in
  testing (3000+ local + concurrent real-site requests). If you see a stall or
  crash, it is almost certainly plumbing — read `DESIGN.md` §5.
