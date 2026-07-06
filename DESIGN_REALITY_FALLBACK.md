# REALITY fallback (anti-active-probing) — design

## Problem

REALITY's whole point is to be indistinguishable from a real HTTPS site under
**active probing**: when a prober (or a stray browser / scanner) connects without
a valid REALITY auth token, the server must behave *exactly* like the real site
it borrows — same certificate, same handshake, same page.

The current Envoy implementation does **not** do this. Authentication happens
inside BoringSSL's `select_certificate_cb` (`reality_handshaker.cc:129-131`); on
failure it returns `ssl_select_cert_error`, which makes BoringSSL emit a TLS
alert and abort. Measured behavior:

```
$ openssl s_client -connect <server>:8443 -servername www.apple.com
... sslv3 alert handshake failure (alert 40); no peer certificate
```

A prober sees a TLS handshake that *starts and then fails* — an anomaly almost no
real HTTPS server exhibits. This single observable defeats **all** of the TLS/H2
fingerprint work: the prober never needs to analyze JA4 or the mirrored
ServerHello; it just connects and sees the handshake break.

## Why it can't be fixed inside the handshaker

`select_certificate_cb` fires *inside* `SSL_do_handshake()`, after BoringSSL has
already consumed the ClientHello and bound the record layer to its BIO. At that
point the raw ClientHello bytes cannot be "un-read" and re-forwarded as plain TCP.
Returning anything but success emits an alert. So xtls-style transparent fallback
is impossible from within the transport socket.

## How xtls does it (reference)

xtls/reality authenticates at the **byte/L4 layer, before TLS**. It wraps the
client conn in a `MirrorConn` that mirrors every read to a dialed-out connection
to the real `Dest`, while peeking the ClientHello to run X25519/HKDF/AES-GCM auth:
- **auth success** → hijack the handshake into REALITY (borrowing dest's
  ServerHello shape);
- **auth failure** → pure TCP pipe: `client ⟷ server ⟷ dest`. The prober talks
  to the real site; the server is a transparent proxy.

The decision is made *before* TLS is terminated locally. That is the key.

## Design for Envoy (composition, not a rewrite)

Envoy already ships every primitive needed. The decision is moved out of the
transport socket and up to **L4 (a listener filter)**, then the connection is
routed to one of two filter chains via the unified `filter_chain_matcher`.

```
                         ┌─────────────────────────────────────────┐
   prober / client ──────►  listener filter: reality_authenticator │
        (raw TCP)        │   - MSG_PEEK the ClientHello (no drain)  │
                         │   - buffer-only SSL_CTX -> SSL_CLIENT_HELLO
                         │   - run REALITY auth (pure function)     │
                         │   - setDynamicMetadata(authenticated)    │
                         └───────────────┬─────────────────────────┘
                                         │  filter_chain_matcher
                                         │  (input: dynamic_metadata)
                    authenticated=true   │   authenticated=false
              ┌──────────────────────────┴───────────────────────────┐
              ▼                                                        ▼
   filter chain "reality"                              filter chain "fallback"
   transport_socket: TLS + custom_handshaker(reality)  transport_socket: raw_buffer
   -> existing live-mirror path (unchanged)            network filter: tcp_proxy
                                                       -> cluster dest (STRICT_DNS
                                                          www.apple.com:443)
```

Because the listener filter uses `MSG_PEEK` and never calls `drain()`, the full
original ClientHello stays in the kernel socket buffer, so **both** downstream
chains re-read the complete original bytes:
- the reality chain hands them to BoringSSL for the real REALITY handshake;
- the fallback chain lets tcp_proxy forward them verbatim to the real dest.

### Component 1 — listener filter `reality_authenticator`

- Modeled on `tls_inspector` (`extensions/filters/listener/tls_inspector/`).
- `maxReadBytes()` grows up to 16 KiB until a full ClientHello is peeked.
- Parses it with a buffer-only `SSL_CTX_new(TLS_with_buffers_method())` +
  `SSL_CTX_set_select_certificate_cb`, exactly as tls_inspector does, to obtain a
  `const SSL_CLIENT_HELLO*` from raw bytes without any handshake.
- Runs the REALITY auth check and writes the result:
  `cb.setDynamicMetadata("envoy.filters.listener.reality", {authenticated: bool})`
  (or `filterState()`), then returns `Continue`.
- Auth is synchronous pure crypto (no I/O), so no async suspension is needed here.

### Component 2 — refactor the auth check into a free function

`extractAndVerifyAuth` (`reality_handshaker.cc:219`) is already effectively pure:
inputs are a parsed `SSL_CLIENT_HELLO*` plus three config values
(`private_key`, `short_id`, `max_time_diff_seconds`); output is a bool. It touches
no live `SSL*` session state. Extract it into a shared free/static function:

```cpp
// reality_auth.h  (shared by the handshaker and the listener filter)
bool realityVerifyAuth(const SSL_CLIENT_HELLO* client_hello,
                       absl::Span<const uint8_t> private_key,
                       absl::string_view short_id,
                       uint32_t max_time_diff_seconds,
                       /*out*/ RealityAuthContext* ctx);  // peer_pub, group, etc.
```

Both the transport-socket handshaker and the listener filter call it. Single
source of truth for the auth algorithm.

### Component 3 — filter chains + fallback cluster

- Enable the unified matcher on the listener: `Listener.filter_chain_matcher`.
- Matcher input: `envoy.matching.inputs.dynamic_metadata` reading
  `envoy.filters.listener.reality:authenticated`.
- `authenticated=true` → the existing REALITY TLS filter chain (unchanged: TLS
  DownstreamTlsContext + `custom_handshaker: reality`, live mirror intact).
- `authenticated=false` → a fallback chain: **raw_buffer** transport socket +
  `tcp_proxy` to a `dest` cluster (STRICT_DNS / LOGICAL_DNS → `www.apple.com:443`).
  raw_buffer is mandatory: the fallback path must not terminate TLS, so the
  prober's original ClientHello is forwarded byte-for-byte to the real dest.

## Auth-runs-twice note

With this design REALITY auth runs at L4 (to route) and, for authenticated
connections, effectively again inside the handshaker (which still needs the
peer_pub / group to drive the mirror + ECDH). That is acceptable: the check is a
few µs of pure crypto. If we want to avoid the double parse, the L4 filter can
stash the derived `RealityAuthContext` in `filterState()` and the handshaker can
read it back — an optimization, not required for correctness.

## What this buys vs. costs

- **Buys:** true xtls-grade anti-active-probing. A prober connecting without a
  token gets the *real* dest's certificate, handshake, and page — no observable
  anomaly. This is the difference between "REALITY" and "a TLS server that RSTs
  weird connections."
- **Costs:** one new listener filter (+~tls_inspector-sized), a small refactor of
  the auth check into a shared function, and a config shape change (two filter
  chains + `filter_chain_matcher` + a dest cluster). No BoringSSL patch changes.
  No change to the live-mirror success path.

## Open questions / risks

1. **Timing/RTT parity — analyzed, low risk.** xtls mirrors bytes to dest from
   the first read (speculative dial concurrent with reading the ClientHello), so
   the dest's ServerHello timing matches a real visit. The serial design here
   (peek → verdict → dial on failure) adds one `server→dest` TCP-connect RTT
   (`Rsd`) that xtls hides. Analysis:

   - **Measured `Rsd` ≈ 2.5 ms** to `www.apple.com` from a well-connected host
     (apple is on Akamai/aaplimg CDN, edge is close). For a dest on a near CDN
     this extra delay is negligible.
   - **CDN anycast blurs the baseline.** A prober connecting to `www.apple.com`
     is anycast-routed to *its* nearest edge; our server reaching `www.apple.com`
     hits *our* nearest edge — different nodes, different RTTs. There is no single
     "true baseline" for the prober to diff against; the ~2.5 ms is lost in the
     natural jitter of CDN node selection.
   - **Two mitigations if needed:**
     - **(A) serial (this design):** simple, dials dest only on failure (doesn't
       bother dest with legitimate traffic). Extra latency ≈ `Rsd`.
     - **(B) speculative dial (xtls-style):** the L4 filter dials dest in parallel
       with the peek; failure → dest already connected, extra latency ≈ 0; success
       → drop the speculative connection. Matches xtls parity exactly, at the cost
       of dialing dest for every connection (including legitimate ones). Keep as an
       optional optimization / TODO.
   - **Strongest mitigation — dest selection.** Pick a dest with a very low
     `server→dest` RTT (same DC / same city / near CDN), pushing `Rsd` to 1–3 ms
     and dissolving the parity concern at the root. This is another "find a
     neighbor" criterion: the dest must not only support TLS1.3 + H2 +
     X25519MLKEM768, but also be **network-close to the VPS**.

   Verdict: serial (A) is sufficient for a near-CDN dest; speculative (B) is a
   documented optional upgrade for far/high-precision-probe scenarios.
2. **SNI gating.** xtls also rejects (falls back) when SNI isn't in the allowed
   set. The L4 filter should apply the same gate: SNI not matching → fallback,
   before even attempting auth.
3. **Fallback bandwidth shaping.** xtls rate-limits fallback traffic
   (`LimitFallbackUpload/Download`) to mimic a real site. Optional; tcp_proxy can
   be paired with a bandwidth limit filter if needed.
4. **Half-open / RST semantics** on the fallback pipe should mirror xtls
   (propagate FIN as CloseWrite, RST as Close) to avoid a distinguishable
   teardown signature.
```
