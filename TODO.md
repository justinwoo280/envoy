# NaiveProxy-REALITY — TODO / open items

Status snapshot of what is done, what is untested, and what remains. See
`DESIGN.md` for rationale and `NAIVE_SERVER_CONFIG.md` for server setup.

## Done and verified

- [x] End-to-end REALITY over TCP/H2: plain X25519 and PQC (X25519MLKEM768),
      HTTP 200; real sites (cloudflare/google/github/wikipedia).
- [x] Four data-plane crashes fixed (cross-thread heap corruption; see
      `DESIGN.md` §5.1). Zero crashes under 3000+ local + concurrent real-site load.
- [x] Intermittent ~15 s stall fixed (fast-open dropped first payload; see
      `DESIGN.md` §5.2). Verified 0 stalls: 100 sequential + 100 concurrent
      direct SOCKS5, 60 sequential + 20 UDP via TUN.
- [x] SNI/JA4 fidelity: cipher hash byte-for-byte vs. real Chrome; modern Chrome
      extension set (incl. ALPS 0x44cd).
- [x] UDP-over-TCP (UoT) end-to-end (three plumbing bugs fixed).
- [x] `bind-interface` (`""` / `"auto"` / explicit name) — socket-layer NIC bind
      for loop-free TUN. Verified in a two-container topology with no bypass route.
- [x] System-wide TUN mode via `hev-socks5-tunnel` + hook scripts (Linux/macOS/
      Windows), auto-variant only. Linux tested end-to-end.
- [x] Docs: `DESIGN.md`, `NAIVE_SERVER_CONFIG.md`, `NAIVE_BUILD_RUNBOOK.md`,
      `NAIVE_TRIM.md`, naiveproxy `tun/README.md`.
- [x] Windows x64 client build (CI `build-win` job). All changes — including
      bind-interface's `IP_UNICAST_IF` path — compile and link; artifact is a
      valid PE32+ `naive.exe` importing IPHLPAPI.DLL and WS2_32.dll.

## Untested / needs a real environment

- [ ] macOS and Windows TUN hook scripts: logic is aligned with the tested Linux
      variant but **not run on real macOS/Windows**. Verify on hardware.
- [ ] `bind-interface: "auto"` runtime probe on macOS (`IP_BOUND_IF`) and Windows
      (`IP_UNICAST_IF`) against a real physical NIC (compiles on Windows; only
      Linux `SO_BINDTODEVICE` exercised at runtime so far).
- [ ] macOS client build (CI job not yet added; upstream build.yml has mac jobs).
- [ ] musl-static client build (optional release variant).

## Cleanup / hygiene

- [ ] The Envoy fork history has a temporary-diagnostics commit (`d7bec9d8`)
      fully reverted by the fix (`7082b7c4`). Net tree is clean; decide whether to
      squash before any upstreaming.
- [ ] Consider removing the `router` filter + dummy cluster if HCM validation
      allows (per `NAIVE_TRIM.md` staged trimming) to shrink the binary further.

## Possible future work (not committed)

- [ ] Idle/tunnel timeout tuning and surfacing them as config (currently 5 min /
      15 min defaults).
- [ ] Metrics/observability for the naive filter (connection counts, UoT sessions).
- [ ] Revisit whether `fast_open` should default on or off now that the
      dropped-payload race is fixed.
