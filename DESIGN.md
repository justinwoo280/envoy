# NaiveProxy-REALITY — design, decisions, and hard-won lessons

This document captures the *why* behind the NaiveProxy-REALITY project: the
overall architecture, the design decisions we committed to, and the bugs whose
root causes taught us something worth remembering. It is deliberately opinionated
and specific — it is the map we wish we'd had at the start.

Companion docs:
- `NAIVE_TRIM.md` / `NAIVE_BUILD_RUNBOOK.md` — how to build the trimmed server.
- `source/extensions/filters/http/naive_forward_proxy/` — the server data-plane filter.
- `source/extensions/transport_sockets/reality/` — the REALITY handshaker.
- naiveproxy fork `src/net/tools/naive/tun/README.md` — system-wide TUN mode.

## 1. What this is

A NaiveProxy-compatible proxy where the **client** is NaiveProxy (Chromium net
stack) and the **server** is Envoy, both speaking **REALITY** as the TLS layer.
REALITY makes the proxy's TLS handshake indistinguishable from a real visit to a
chosen "mirror" site (`server_name`), defeating active TLS-fingerprint probing.

- Transport: TCP and HTTP/2 only. **No H3/QUIC.**
- REALITY uses **Ed25519 ephemeral certificates**, faithful to the upstream
  `xtls/reality` design.
- Release artifact: a single `naive` client binary (glibc Linux + Windows), with
  Envoy as the server. musl-static is an optional extra.

## 2. The moat vs. the plumbing

The single most useful framing we found:

> The **crypto/protocol core** (the BoringSSL REALITY patch, the handshaker) is
> the moat. It is small, audited, and — across this entire effort — has **never
> crashed**. Every crash and every stall lived in the **data-plane / framework
> glue** (the Envoy filter, socket wiring, event registration).

Act accordingly: when something breaks under load, suspect the plumbing, not the
crypto. We wasted the least time whenever we trusted this rule.

## 3. Architecture

```
        client host                                   VPS (remote, never colocated)
 ┌──────────────────────────┐                   ┌──────────────────────────────────┐
 │ apps → (SOCKS5/TUN) →     │   REALITY over    │  Envoy                            │
 │   naive  ───────────────► │   TCP / HTTP2     │   tls_inspector                   │
 │   (Chromium net stack)    │ ════════════════► │   → REALITY custom_handshaker     │
 │                           │                   │   → HCM (HTTP/2)                   │
 │                           │                   │   → naive_forward_proxy filter    │
 └──────────────────────────┘                   │        → upstream TCP/UDP → internet
                                                 └──────────────────────────────────┘
```

- The client dials the server over what looks exactly like TLS to the mirror
  site. Inside, it's HTTP/2; each proxied connection is an H2 stream carrying an
  HTTP `CONNECT`.
- The server terminates REALITY, runs an HTTP filter that authenticates the
  `CONNECT`, opens the upstream (TCP, or UDP via UoT), and relays bytes.

### Server config invariants (get these wrong = silent failure)

- `codec_type: HTTP2` on the HCM.
- `alpn_protocols: ["h2"]` — **mandatory**. REALITY + H2; forgetting `h2` breaks
  ALPN negotiation.
- `custom_handshaker: { name: envoy.tls_handshakers.reality }`.
- The `naive_forward_proxy` HTTP filter, plus a dummy `STATIC` cluster (the
  filter builds its own upstreams; the cluster exists to satisfy config
  validation).
- The handshaker sets groups `X25519MLKEM768:X25519` and declares
  `provides_sigalgs`/`provides_certificates`; because it provides sigalgs, the
  server signing prefs must be set explicitly to `SSL_SIGN_ED25519` (the injected
  leaf is an Ed25519 cert).

## 4. Key design decisions

| Decision | Rationale |
|----------|-----------|
| REALITY uses Ed25519 ephemeral certs; TCP/H2 only, no QUIC | Faithful to upstream `xtls/reality`; smaller surface; QUIC fingerprinting is a different, harder problem we chose not to take on. |
| Client is NaiveProxy (Chromium), server is Envoy | The client rides Chrome's real TLS ClientHello (see §6 fingerprinting); Envoy gives a production-grade, extensible server data plane. |
| Single `naive` binary as the release | Users deploy one file. The server is our concern, not theirs. |
| **TUN via a separate `hev-socks5-tunnel` process**, not built into naive | Keeps the release a single binary and keeps tun2socks glue out of the crypto core. hev is MIT (no license contagion across a process boundary). We ship only a usage guide + hook scripts. |
| Loop prevention via **`bind-interface` at the socket layer**, not routing tricks | naive binds outbound sockets to the physical NIC (`SO_BINDTODEVICE` / `IP_BOUND_IF` / `IP_UNICAST_IF`). The proxy→VPS hop never enters the tun, so no per-server bypass route is needed. This dodges the iptables-mark routing-decision timing trap and the separate-table+rule ordering trap. |
| LICENSE without "All rights reserved" | Avoids a Debian DFSG conflict. |

## 5. The data-plane bugs (and their root causes)

All five below were in the Envoy server filter. The moat never moved.

### 5.1 Four crashes — one true root cause: cross-thread heap corruption

Under concurrent load the server died with either
`libc++abi: Pure virtual function called!` or
`*** buffer overflow detected ***` + `Epoll ADD failed: Bad file descriptor`.
Four distinct fixes, but the unifying theme is **objects created/destroyed or
driven on the wrong thread**, or **used after free during teardown**:

1. **`closeAll()` didn't remove connection callbacks** before closing the
   upstream → a re-entrant destroy path invoked callbacks on a dying object.
   Fix: detach callbacks first.
2. **Upstream connection freed synchronously** during a re-entrant destroy.
   Fix: `dispatcher().deferredDelete()` the upstream so it outlives the current
   call stack.
3. **`TcpReadFilter` dangling back-reference.** The deferred-deleted upstream (and
   its read filter) can outlive the owning filter, which the HTTP layer destroys
   synchronously on stream reset. A late `onData()` then called a virtual on a
   destroyed object. Fix: a shared `alive_` flag the parent clears; late
   callbacks become no-ops. Also: in `relayTcpUpstreamToClient`, update all
   member state **before** `encodeData(end_stream=true)`, because that call can
   synchronously reset the stream and free `this`.
4. **DNS resolver / connections on the main-thread dispatcher.** The `Config`
   held the main-thread dispatcher; using it from workers created and tore down
   connections on a different thread than the one operating them, corrupting the
   heap (c-ares fd/epoll state is not thread-safe). Fix: use
   `decoder_callbacks_->dispatcher()` (the worker thread) for everything, and
   create the DNS resolver **per worker** via `createDnsResolver()`.

**Lesson:** in Envoy, *every* per-stream network object, timer, file event, and
`deferredDelete` must live on and be driven by the worker-thread dispatcher.
Diagnosis method that worked: an **unstripped** binary + `gdb` on the core dump
(the tell was `RawBufferSocket::onConnected this=null`). Note the split-dwarf
`.dwo` files are absent in the artifact, so `objcopy --strip-debug` the unstripped
binary to keep the symbol table while dropping broken DWARF before loading in gdb.

### 5.2 The intermittent ~15 s stall — dropped first payload (fast-open race)

Symptom: ~13% of rapid sequential new tunnels (direct SOCKS5), amplified to ~25%
through the TUN path, would stall for exactly ~15 s, then recover. Not a crash;
throughput otherwise fine.

**Why it was hard:** the worker thread was *not* blocked. gdb snapshots during
the stall showed it idle in `epoll_wait` with a healthy timeout — a normal event
loop. So it was **an event that never fired**, not a stuck syscall. tcpdump
confirmed the server accepted the client's data at the TCP layer (kernel ACK) but
the application produced nothing for 15 s.

**Root cause (confirmed with temporary `NAIVE_DIAG` logging):** in **fast-open**
mode the `200 OK` is sent from `decodeHeaders`, so the client immediately pushes
its first payload (a TLS ClientHello) — while the server's upstream TCP connect
is still **in flight**. The old `relayClientToTcpUpstream()` did:

```cpp
if (!tcp_upstream_ || !tcp_upstream_connected_) return;  // silently DROP
// ... and decodeData returned StopIterationNoBuffer, so Envoy didn't keep it either
```

The ClientHello was **lost**. The target never saw a handshake, so it never
replied; ~15 s later a timeout/retransmit tore down and the retry succeeded. The
race between "connect completes" and "client body arrives" made it intermittent.

**Fix:** always strip padding (the padding decoder is streaming/stateful, so it
must keep advancing), buffer the resulting plaintext in `pending_upstream_data_`
when the upstream isn't connected yet, and flush it in
`onTcpUpstreamEvent(Connected)` via `flushPendingToUpstream()`. The `end_stream`
half-close is likewise deferred until connected to avoid a duplicate end_stream
write.

**Lesson:** if a filter returns `StopIterationNoBuffer`, it has taken ownership of
that data — Envoy will not re-deliver it. Never drop bytes on a "not ready yet"
path; buffer them. And: an idle-in-`epoll_wait` worker during a stall means a
**missing/mis-armed event**, not a deadlock — chase the event wiring, not locks.

## 6. Fingerprinting fidelity (SNI / JA4 / cipher)

- **SNI bug:** naive omitted the REALITY `server_name` because it was gated by
  `if (!host_is_ip_address)`. REALITY must send `server_name` unconditionally.
  Fix in `ssl_client_socket_impl.cc` (also see `kVerifyPrefsReality`).
- **JA4 verified byte-for-byte against real Chrome:** the cipher hash matched
  (`8daaf6152771`), and the extension set matched modern Chrome exactly
  (including the newer ALPS `0x44cd`). REALITY does **not** permute extensions,
  so the fixed order is not exposed under JA4's hashing.
- **Cipher adoption (BoringSSL patch, "scheme B"):** the server patch adopts the
  client's cipher and replaces the key_share, with the mirror hook driving the
  ServerHello. This is the moat and has been stable.

## 7. UDP-over-TCP (UoT)

Standard SOCKS5 `UDP ASSOCIATE`, tunneled as UoT over the H2 stream. Three bugs,
all plumbing:

1. Server `extractTarget` rejected `port 0`; the UoT magic host must be allowed
   through (client sends `CONNECT` authority with port 0). Magic host:
   `sp.v2.udp-over-tcp.arpa` (legacy `sp.udp-over-tcp.arpa`).
2. naive's SOCKS5 UDP ASSOCIATE relay had the reply port's two bytes swapped.
3. The server's UDP relay socket lacked `SOCK_NONBLOCK`, so the reverse-path
   `onFileEvent` never fired.

hev must run UDP mode as `udp: 'udp'` (real SOCKS5 ASSOCIATE, which naive
supports) — **not** the `'tcp'` private protocol.

**Lesson:** the same class as §5.2 — a socket created without `SOCK_NONBLOCK`, or
an event source not armed correctly, presents as "works for small/first case,
silently stalls afterwards."

## 8. Operational notes worth keeping

- **Shell/background-process trap:** a spawned background process inherits the
  parent command's stdout pipe, so a tool waiting for EOF hangs until timeout.
  Use `setsid` + `</dev/null` + explicit redirection when spawning; use
  `pkill -x` (exact name), not `pkill -f` (which matches the killer itself).
- **CI:** the two forks (`justinwoo280/{envoy,naiveproxy}`, branch
  `build-naive-server`) produce artifacts in ~20 min (Envoy longer). The Envoy CI
  also emits an `envoy-unstripped` for gdb.
- **Client is the bottleneck, not the server.** Under concurrent load the naive
  client pins a core (the PQC handshake is expensive); the Envoy server sits
  around 10% CPU.
