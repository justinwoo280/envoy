# NaiveProxy-REALITY Envoy server — configuration guide

How to configure the `envoy-min` server. For *building* the binary see
`NAIVE_BUILD_RUNBOOK.md`; for architecture and rationale see `DESIGN.md`; for the
anti-active-probing fallback design see `DESIGN_REALITY_FALLBACK.md`.

**The server must run on a remote VPS — never colocated with the client.**

---

## Step 0 — Generate the keys (do this once)

REALITY needs an X25519 key pair (server keeps the private half, client gets the
public half) and a shared `short_id`. Generate all three with `openssl` +
`python3` (no extra tools):

```sh
# X25519 key pair
openssl genpkey -algorithm X25519 -out reality.pem

python3 - <<'PY'
import base64, subprocess
der  = subprocess.check_output(["openssl","pkey","-in","reality.pem","-outform","DER"])
pub  = subprocess.check_output(["openssl","pkey","-in","reality.pem","-pubout","-outform","DER"])
print("private_key (server):", base64.b64encode(der[-32:]).decode())
print("public_key  (client):", base64.b64encode(pub[-32:]).decode())
PY

# short_id: any 1..8 random bytes, base64 (server and client must match)
openssl rand 8 | base64
```

Keep `private_key` on the server, give `public_key` to the client, and put the
same `short_id` on both.

---

## Recommended config (live mirror + anti-probing fallback)

This is the configuration validated end-to-end. It has two behaviors:

- **Authenticated clients** (your naive) → REALITY tunnel, with the ServerHello
  mirrored **live** from the real site per connection.
- **Everyone else** (scanners, active probers, stray browsers) → transparently
  proxied to the real site, so they see the real site's certificate and page —
  indistinguishable from visiting it directly. This is what defeats active
  probing.

Replace `CHANGE_ME`, the keys, and `www.apple.com` (your chosen *dest*; see
"Choosing a dest" below).

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
    # REALITY L4 authenticator: peeks the ClientHello, runs REALITY auth, and
    # writes the verdict to filter state so the matcher below can route.
    - name: envoy.filters.listener.reality_authenticator
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.reality_authenticator.v3.RealityAuthenticator
        private_key: "<base64 X25519 private key>"
        short_id: "<base64 short id>"
        max_time_diff_seconds: 90
    # Route on the auth verdict:
    #   authenticated == "true"  -> reality chain (tunnel)
    #   otherwise (probers)      -> fallback chain (transparent proxy to dest)
    filter_chain_matcher:
      matcher_tree:
        input:
          name: authd
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.FilterStateInput
            key: envoy.filters.listener.reality_authenticator.authenticated
        exact_match_map:
          map:
            "true":
              action:
                name: to_reality
                typed_config:
                  "@type": type.googleapis.com/google.protobuf.StringValue
                  value: "reality"
      on_no_match:
        action:
          name: to_fallback
          typed_config:
            "@type": type.googleapis.com/google.protobuf.StringValue
            value: "fallback"
    filter_chains:
    - name: reality
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: naive
          codec_type: HTTP2                       # (1) MUST be HTTP2
          route_config:
            name: local
            virtual_hosts:
            - name: naive
              domains: ["*"]
              routes:
              - match: { connect_matcher: {} }
                route:
                  cluster: dummy                  # (2) dummy STATIC cluster
                  upgrade_configs:
                  - { upgrade_type: CONNECT, connect_config: {} }
          http_filters:
          - name: envoy.filters.http.naive_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.naive_forward_proxy.v3.NaiveForwardProxy
              username: "CHANGE_ME"
              password: "CHANGE_ME"
              fast_open: true
              max_padding_size: 256
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            alpn_protocols: ["h2"]                # (3) MUST include h2
            custom_handshaker:                    # (4) REALITY handshaker
              name: envoy.tls_handshakers.reality
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.transport_sockets.reality.v3.RealityConfig
                private_key: "<base64 X25519 private key>"   # same as above
                short_id: "<base64 short id>"                # same as above
                mirror_target: "www.apple.com:443"           # (5) live mirror
                mirror_dial_timeout_seconds: 5
                max_time_diff_seconds: 90
    - name: fallback
      # No transport_socket => raw_buffer (plaintext passthrough). Do NOT put a
      # TLS transport socket here, or the prober's ClientHello won't reach dest.
      filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: fallback
          cluster: dest_apple

  clusters:
  - name: dummy                                   # satisfies CONNECT route validation;
    type: STATIC                                  # the filter builds its own upstreams.
    load_assignment:
      cluster_name: dummy
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: 127.0.0.1, port_value: 1 }
  - name: dest_apple                              # the real site probers get proxied to.
    type: STRICT_DNS                              # must resolve + reach the dest.
    load_assignment:
      cluster_name: dest_apple
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: www.apple.com, port_value: 443 }
```

> **Note on `dest_apple` cluster type.** Use `STRICT_DNS` / `LOGICAL_DNS` with the
> dest hostname if your build includes that cluster factory. If config load fails
> with `Didn't find a registered cluster factory implementation for
> 'envoy.cluster.logical_dns'`, your binary was trimmed without it — either add
> it back (`NAIVE_TRIM.md`) or use `type: STATIC` with the dest's resolved IP.

---

## The things you cannot get wrong

1. **`codec_type: HTTP2`** — naive tunnels each proxied connection as an HTTP/2
   `CONNECT` stream.
2. **A dummy `STATIC` cluster** referenced by the CONNECT route. The
   `naive_forward_proxy` filter opens its own upstreams and returns
   `StopIteration`, so the cluster is never dialed — but route validation
   requires it to exist.
3. **`alpn_protocols: ["h2"]`** — without `h2`, ALPN breaks and the client can't
   establish the H2 session. The most common "validates but doesn't work" bug.
4. **`custom_handshaker: envoy.tls_handshakers.reality`** with valid
   `private_key` / `short_id` matching the client.
5. **`mirror_target`** — `host:port` of the real site to mirror live. **The
   `reality_authenticator` and the handshaker must use the same `private_key`,
   `short_id`, and the dest hostname must match the client's `server_name`.**

---

## REALITY / mirror fields

| Field | Where | Meaning |
|-------|-------|---------|
| `private_key` | authenticator + handshaker | Raw 32-byte X25519 private key, base64. Pairs with the client's `public_key`. Put the **same value** in both places. |
| `short_id` | authenticator + handshaker | Base64 (1..8 bytes). Must byte-match the client. |
| `mirror_target` | handshaker | `host:port` of the real site. The server dials it **per connection** and captures its live ServerHello — so the client sees the real site's exact fingerprint. |
| `mirror_dial_timeout_seconds` | handshaker | How long to wait for the live dial before giving up (falls back to `mirror_server_hello` if configured, else fails). |
| `mirror_server_hello` | handshaker (optional) | Base64 of a pre-captured ServerHello, used as a **static fallback** only if the live dial fails. Not required when `mirror_target` is set. |
| `max_time_diff_seconds` | both | Clock-skew tolerance for the REALITY auth timestamp (e.g. 90). |

**Live vs static mirror.** With `mirror_target` set, you do **not** need to
pre-capture a ServerHello — the server grabs a fresh one from the real site on
every handshake, matching whatever group the client negotiated (X25519 or
X25519MLKEM768). This is the recommended mode. `mirror_server_hello` alone
(static) still works but is a single frozen capture.

---

## Choosing a dest (mirror_target)

The dest is the real site you borrow. Choosing it well is a security decision,
not cosmetic:

- **Must support TLS 1.3 + HTTP/2**, and ideally the same key_share groups your
  client offers (X25519MLKEM768). Verify:
  `openssl s_client -connect HOST:443 -groups X25519MLKEM768 -tls1_3` should
  report `Negotiated TLS1.3 group: X25519MLKEM768`.
- **Must be network-close to your VPS.** A prober can compare "connecting to you"
  vs "connecting to the dest directly"; if your server→dest round-trip is large,
  the timing difference is observable. Aim for `server→dest` RTT well under
  ~10 ms. Big CDNs (apple / microsoft / cloudflare) have edge nodes almost
  everywhere, so they are close to most VPS locations.
- **Avoid** obscure single-datacenter sites (likely far from your VPS → timing
  leak) and sites that reject unknown SNI at the edge.
- **Rule of thumb:** pick a large CDN-fronted site that is popular in your VPS's
  region. See `DESIGN_REALITY_FALLBACK.md` for the timing analysis.

---

## Validate before serving

```sh
./envoy-min -c your_config.yaml --mode validate    # config load only, no traffic
./envoy-min -c your_config.yaml --concurrency 1 -l warning
```

Quick self-test once it's running (from anywhere that can reach the VPS):

```sh
# A plain TLS probe MUST see the real dest's certificate (fallback working):
openssl s_client -connect YOUR_VPS_IP:8443 -servername www.apple.com </dev/null \
  | grep -E "subject=|Verify return"
# -> should show CN = www.apple.com, O = Apple Inc., Verify return code: 0 (ok)
```

If a plain probe gets a `handshake failure` instead of the real cert, the
fallback chain is misconfigured (check the matcher and the raw_buffer/tcp_proxy
fallback chain).

---

## Operational notes

- **Remote VPS only.** The client handles its own local loop-prevention
  (`bind-interface` / TUN hooks); the server does not participate.
- The server is lightly loaded (~10% CPU under concurrent load); the naive
  **client** is the bottleneck (the PQC handshake pins a core).
- Zero crashes / zero stalls under concurrent load in testing (mixed authenticated
  + prober traffic, thousands of requests). A stall or crash is almost certainly
  plumbing — see `DESIGN.md` §5.
- The fallback path proxies unauthenticated traffic to the real dest. This costs
  a little upstream bandwidth to the dest, which is the price of being
  probe-resistant.
```
