# NaiveProxy-REALITY Envoy server — configuration guide

How to configure the `envoy-min` server. For *building* the binary see
`NAIVE_BUILD_RUNBOOK.md`; for architecture and rationale see `DESIGN.md`; for the
anti-active-probing fallback design see `DESIGN_REALITY_FALLBACK.md`.

**The server must run on a remote VPS — never colocated with the client.**

---

## Step 0 — Generate the keys (do this once)

REALITY needs an X25519 key pair (server keeps the private half, client gets the
public half) and a shared `short_id`. The encoding matches the rest of the
REALITY ecosystem so the same strings are reused verbatim across this server,
the naive client, and sing-box:

- keys: **base64url** (Go RawURLEncoding), exactly what `xray x25519` prints
- short_id: a **hex** string, 1..8 bytes (2..16 hex chars)

The simplest way is the standard tool (also used by Xray/sing-box):

```sh
# X25519 key pair (PrivateKey -> server, Password/PublicKey -> client)
xray x25519

# short_id: any 1..8 random bytes as hex (server and client must match)
openssl rand -hex 8
```

Or with openssl + python (no xray), producing the same base64url encoding:

```sh
openssl genpkey -algorithm X25519 -out reality.pem
python3 - <<'PY'
import base64, subprocess
der = subprocess.check_output(["openssl","pkey","-in","reality.pem","-outform","DER"])
pub = subprocess.check_output(["openssl","pkey","-in","reality.pem","-pubout","-outform","DER"])
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
print("private_key (server, base64url):", b64u(der[-32:]))
print("public_key  (client, base64url):", b64u(pub[-32:]))
PY
openssl rand -hex 8   # short_id (hex)
```

Keep `private_key` on the server, give `public_key` to the client, and put the
same `short_id` (hex) on both. These are the identical strings you would use in
an Xray/sing-box REALITY config — no conversion.

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
        private_key: "<base64url X25519 private key>"
        short_id: "<hex short id>"
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
                private_key: "<base64url X25519 private key>"   # same as above
                short_id: "<hex short id>"                # same as above
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
  ~10 ms. Big CDNs (apple / microsoft) have edge nodes almost everywhere, so
  they are close to most VPS locations.
- **Mind the relay-traffic cost of a global-anycast CDN dest.** When an
  off-allowlist SNI arrives, REALITY forwards it to your **fixed** `dest`. If
  that dest is a *shared anycast CDN edge*, the edge routes the forwarded
  SNI/Host to whatever tenant it hosts — so your node can relay to that CDN's
  tenant set. On a **global-anycast CDN (Cloudflare / Fastly / CloudFront)** that
  is the CDN's *entire* customer base: an attacker deploys their own origin on
  the CDN (free account, SNI == Host — so the CDN's anti-domain-fronting `421`
  never triggers) and relays it through you, spending your bandwidth and IP
  reputation. *Verified across sing-box, naive-Envoy, and the official Xray-core
  — this is inherent to REALITY + a global-anycast dest, not an implementation
  bug.*
- **This is a cost, not an insecurity — and you MUST imitate it.** Serving a real
  CDN edge's multi-tenant behaviour (many domains, `alert 80` on no-SNI) is
  *correct camouflage*; a genuine CDN edge does exactly this. Forcing a single
  fixed SNI and rejecting everything else would make your node look *unlike* the
  edge it imitates — a worse, distinguishing tell. So you stay unobservable; you
  only pay in *relayed traffic*.
- **Avoid** obscure single-datacenter sites (likely far from your VPS → timing
  leak) and sites that reject unknown SNI at the edge.
- **Dest priority (best → worst):**
  1. **Single-origin neighbour (preferred).** A network-close site on its own
     origin: no multi-tenancy, so no relay surface at all. Best on both the
     timing axis and the relay-cost axis.
  2. **Segmented / high-barrier CDN (acceptable) — e.g. Akamai.** Edges serve
     only a bounded local tenant set, and the enterprise contract barrier stops a
     casual abuser ("白嫖狗") from planting a relay origin. Keeps the CDN's
     proximity benefits; leaks only the local co-tenant set.
  3. **Global-anycast CDN (least recommended) — Cloudflare / Fastly /
     CloudFront.** Still unobservable, but becomes a potential open relay for the
     CDN's entire customer base. Only a bandwidth/reputation cost, but an
     unbounded one — avoid unless you accept that.
  This axis pulls *against* "network-close" (which favours big CDNs); resolve it
  by preferring a close **single-origin** dest, or a **segmented** CDN, over a
  global-anycast one. See `DESIGN_REALITY_FALLBACK.md` §"Open questions / risks"
  #5 for the full analysis, measured evidence, and the Xray-core cross-check.

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
