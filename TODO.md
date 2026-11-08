# TODO / Roadmap

**Status:** MVP is functionally complete - polling controller, per-container
veth capture via tcpdump, tshark-based enrichment into SQLite, CLI for
attach/detach/status/analyze/report. All 62 unit tests pass.

**Verified 2026-11-08 on Docker Desktop for Mac (Docker 29.7.2):** `sidecar`
mode works end-to-end against a real container - image builds, tcpdump
captures on the shared `eth0`, `enrich` parsed 118 flow rows, and `status`,
`analyze top-talkers|dns|external`, `report` and `report --format html` all
produce correct-looking output (DNS lookups, SNI hostnames, protocol mix).
`watch` mode is still **untested** - it needs a real Linux host (see P0).
Testing turned up one real bug in sidecar-mode reporting (container counted
its own IP as an internet destination) - fixed and live-verified the same
day, see "report.py / analyze.py - bugs found in live testing" below.

## P0 - verify the MVP actually works

- [x] Confirmed (via docs.docker.com and
      [docker/for-mac#7261](https://github.com/docker/for-mac/issues/7261))
      that `network_mode: host` - what `watch`/docker-compose.yml relies on -
      is an unreliable, known-buggy beta feature on Docker Desktop for
      Mac/Windows, including Apple Silicon. Added `nettap sidecar` as the
      Mac/Windows-native alternative (joins the target's netns via
      `--network container:<target>` instead of needing host networking at
      all - see README's "Docker Desktop for Mac / Windows" section).
      Live-tested 2026-11-08 - see next item.
- [ ] Run `docker compose up --build` (`watch` mode) on a real *Linux* Docker
      host (not Docker Desktop) and confirm veth resolution, capture start,
      and enrichment all work end-to-end - this is the only place
      `network_mode: host` is expected to work properly.
- [x] Run `nettap sidecar` (see README) against a real container on Docker
      Desktop for Mac/Windows and confirm packets land in the pcap and in
      `analyze` output. **Done 2026-11-08** (Docker Desktop for Mac): ran an
      `nginx:alpine` target plus a sidecar, generated HTTP + HTTPS traffic to
      example.com from inside it. pcap was written, `enrich` inserted 118
      rows, every `analyze` subcommand and both `report` formats worked.
      Only tested on Mac, not Windows.
- [ ] Confirm the SandboxKey-based `nsenter` trick works on the target Docker
      version/storage driver (logic was reasoned through and unit-tested with
      mocks, not exercised against a live netns).
- [x] **Done 2026-11-08 for `sidecar` mode:** `scripts/integration_test.sh`
      starts a throwaway nginx server + alpine client on their own network,
      a sidecar on each sharing one data dir, sends HTTP client->server and
      HTTPS to example.com, enriches, and checks the flow store with
      nettap's own query functions (14 checks: both containers' IPs
      recorded, HTTP seen in both captures, container matrix links both
      ways, no comma-joined IPs, internet destinations + SNI, no
      container's own IP counted as internet, report self-IPs/bytes/peers).
      `--no-internet` skips the internet checks (11 left). Passed on Docker
      Desktop for Mac 2026-11-08 in both modes, cleans up after itself, and
      exits 1 when a check fails (confirmed with a deliberately broken
      check). Open: add a `watch` mode variant (`attach` + host-network
      nettap container) once there's a Linux host to run it on.
- [x] Verify tshark's default dissectors are available in the slim Docker
      image. **Done 2026-11-08:** the `python:3.11-slim` image correctly
      dissected TLSv1.2/1.3 (including SNI), HTTP, DNS, TCP, ICMPv6 and ARP
      in the live test - no extra packages needed for those.

## P1 - correctness and safety

- [ ] `--network host` containers currently produce a warning and are
      skipped entirely (no dedicated veth exists to capture on). Needs either
      eBPF/cgroup-based attribution or a documented "capture the host
      interface directly and attribute by port" fallback.
- [ ] macvlan/ipvlan network drivers: same problem as host networking - no
      standard veth-to-bridge topology. Needs investigation.
- [ ] Swarm/overlay networks: traffic between containers on different hosts
      travels over a VXLAN tunnel. Capturing on the local veth still sees it,
      but cross-host correlation (matching flows between two hosts' nettap
      instances) isn't implemented - each host is currently an independent
      island.
- [ ] `container_matrix()` in analyze.py resolves the destination container
      by exact IP match against `containers.ip_addresses` - this misses
      traffic through a published host port (the observed dst_ip on the wire
      isn't the peer container's own address). Needs conntrack
      cross-referencing.
- [x] **Fixed 2026-11-08: tcpdump children were orphaned when nettap was
      SIGKILLed.** Live test (nettap run as a non-PID-1 child in the image,
      then `kill -9`): tcpdump kept running as uid 100. Two fixes in
      capture.py: (1) on Linux each tcpdump gets `PR_SET_PDEATHSIG=SIGTERM`
      so the kernel stops it when nettap dies, plus `-Z root`, because
      Debian's tcpdump otherwise switches to the `tcpdump` user and a user
      change clears that signal
      ([prctl(2)](https://man7.org/linux/man-pages/man2/prctl.2.html));
      (2) `reap_orphans()` runs at `watch`/`sidecar` startup and kills
      tcpdumps still listed in `live_sessions`, only if that pid is still
      tcpdump writing the row's pcap pattern (sidecar only reaps its own
      row). After the fix the same live test shows tcpdump (uid 0) gone
      right after `kill -9`; the startup reap was also seen killing the
      orphan before the fix. Integration test still passes. Notes: the
      signal fires when the *thread* that started tcpdump exits, so
      `attach()` must stay on the main thread; the normal Docker setup was
      never affected (nettap is PID 1 there, and the kernel kills the whole
      PID namespace when it exits). Not tested on a bare Linux host.
- [ ] No disk-usage cap on `data/pcap/` - long-running captures will fill the
      disk. Add retention (max age and/or max total bytes, oldest-first
      purge).
- [x] **Fixed (this was the actual root cause of "report doesn't update
      without manually running enrich"):** `_enrich_loop` runs on a
      background thread but was reusing the *main thread's* sqlite3
      connection. sqlite3 connections are only usable from the thread that
      created them by default - so the auto-enrich thread died silently
      (uncaught `sqlite3.ProgrammingError`, no error surfaced anywhere in
      the app) the first time it actually had a row to insert, and never
      ran again. Only a manually-run `nettap enrich` (its own fresh
      process/connection) ever worked, which is exactly the workaround that
      surfaced this. Fixed by having the loop open its own connection from
      a db_path instead of sharing one; also wrapped each iteration in
      try/except so a *future* bug here degrades to "logged and retried"
      instead of "silently dead thread" again. Verified with an actual
      threaded regression test (tests/test_enrich_loop.py), not just a
      mock - it drives `_enrich_loop` on a real background thread against a
      temp DB file and asserts both that a row lands and that the thread is
      still alive afterward.
- [x] **Fixed:** a tcpdump child that exited on its own (crashed, interface
      disappeared, etc.) was never noticed or restarted - captures would just
      silently stop producing new pcaps forever, which read as "the report
      stopped updating" with zero error output anywhere. `CaptureManager.
      restart_dead()` now detects and restarts dead sessions, called from
      both the `watch` controller loop and the `sidecar` loop. Still only
      unit-tested with a fake subprocess (tests/test_capture.py) - watch for
      this in practice, especially around target-container restarts (a
      `sidecar` joined via `--network container:X` does NOT follow `X` if
      the container it names is removed/recreated - that's a still-open gap,
      see the sidecar note below).
- [x] **Fixed:** tcpdump's own stderr (its startup "listening on eth0..."
      line, and any errors) was captured into a pipe nothing ever read, so
      `docker logs <nettap container>` showed nothing useful for diagnosing
      a dead or misbehaving capture. It's now relayed into nettap's own
      logger (`tcpdump[<container>]: ...` lines) as it's produced.
- [ ] **Open gap surfaced by the above:** `nettap sidecar --target X
      --network container:X` binds to whatever container `X` resolves to
      *at `docker run` time*. If that container is later removed and a new
      one takes its place (even with the same name), the sidecar keeps
      capturing the old, now-orphaned network namespace - `restart_dead()`
      won't catch this because the tcpdump process itself doesn't crash, it
      just stops seeing new packets. Needs either: periodically re-checking
      that the target container ID hasn't changed (would need docker.sock
      after all, undoing sidecar mode's main simplification), or clearly
      documenting "recreate the sidecar whenever you recreate its target."

## P2 - richer visibility

- [ ] Swap/augment the tshark-based enrichment with Zeek or Suricata for full
      HTTP request/response logs, JA3/JA3S TLS fingerprints, and file
      extraction - tshark's `-T fields` only gets flow-level metadata today.
- [ ] TLS plaintext visibility: support reading `SSLKEYLOGFILE` (if the
      monitored app is started with it set) so tshark can decrypt TLS during
      analysis; longer term, look at eBPF uprobes on `SSL_read`/`SSL_write`
      (how Pixie does this) for apps that don't cooperate.
- [ ] Replace per-veth tcpdump with an eBPF tc-classifier or cgroup/skb
      program (e.g. via the `cilium/ebpf` Go library, or reuse Inspektor
      Gadget) for: lower overhead at high container counts, in-kernel
      container/cgroup attribution (this also fixes the host-network/macvlan
      gap above), and an optional "counts only, no payload capture" mode for
      high-volume production use.
- [ ] Resolve `dst_ip` to a human-readable name (reverse DNS or a
      known-service table) so `analyze external` doesn't just show raw IPs.

## P3 - scale and usability

- [ ] Swap SQLite for ClickHouse (or Postgres/TimescaleDB) behind the same
      `storage.py` interface once flow volume outgrows a single file - keep
      `insert_flows`/the query functions as the seam.
- [ ] Multi-host: one nettap agent per Docker host, plus a small aggregator
      service so `analyze` can query across a whole fleet instead of one
      host at a time.
- [ ] Web dashboard (Grafana on top of the flow store, or a small bespoke
      UI) for the matrix/top-talkers/external views instead of CLI-only
      JSON.
- [ ] Alerting: flag flows to destinations not on an allowlist, or
      byte-volume spikes per container, and ship them somewhere
      (webhook/Slack/email).
- [ ] Replace the polling controller (default 5s) with a Docker-events
      stream as the primary trigger and polling as just the safety-net
      reconciliation pass, to cut attach latency close to zero.
- [ ] Package as a proper CLI release (PyPI) and/or provide a systemd unit
      as a non-Docker-Compose deployment option.
- [ ] `nettap export --container X --format pcap|json` isn't implemented
      yet - today you export by copying files out of `data/pcap/` directly
      or querying the SQLite DB by hand.

## Known limitations (document, don't silently hide)

- Requires elevated privileges (`NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`) and
  `network_mode: host` for the nettap container itself - only run this in
  environments you trust, on hosts where that's acceptable.
- Payloads are captured for any traffic that isn't already encrypted;
  TLS/SSH etc. give metadata only (IPs, ports, byte counts, SNI, DNS) unless
  the TLS-visibility TODO above is done.
- Single-host only for now (see the multi-host TODO).

## report.py / analyze.py - bugs found in live testing (2026-11-08)

- [x] **Fixed 2026-11-08: in sidecar mode the container listed its own IP
      as an "internet destination".** `sidecar` saved the container with
      `ip_addresses={}`, and `analyze.external_destinations()` counts any
      `dst_ip` not in a known container's `ip_addresses` as internet
      traffic, so every reply packet *into* the container was counted as
      external (25.8 KB of 35.6 KB in the first live test). Fix:
      `discovery.interface_ips()` reads the interface's addresses with
      `ip -j addr show dev <iface>` inside the shared netns (no docker.sock
      needed) and `sidecar` stores them; `report.build_report()` also drops
      its detected self IP from the external list as a backstop for older
      data. Regression tests: `tests/test_sidecar_self_ip.py` (4 of 5 failed
      before the fix). **Live-verified 2026-11-08** on Docker Desktop for Mac
      (nginx:alpine target, HTTP+HTTPS to example.com): `containers` row got
      `{"eth0": "172.17.0.2"}`, `172.17.0.2` no longer appears in
      `analyze external` or the report, and the 25.8 KB now shows correctly
      as "received by this container". The target had no IPv6 address, so
      the IPv6 key path is only unit-tested.
- [x] **Fixed 2026-11-08:** Docker Desktop's internal DNS resolver
      (`192.168.65.7`) showed up as an internet destination.
      `analyze.external_destinations()` now tags every row with
      `scope: internet|local` (`ip_scope()`: publicly routable unicast =
      internet; private/RFC1918, link-local, CGNAT, multicast, broadcast =
      local), plus a `hint` for local rows (e.g. Docker Desktop's
      `192.168.65.0/24` subnet, which runs its DNS server and proxy; the
      subnet is configurable, so it's only a hint - source:
      https://docs.docker.com/desktop/settings-and-maintenance/settings/).
      `analyze external --scope internet|local|all` filters; the report
      shows a separate "Local / private network addresses (not the
      internet)" section. Tests: `tests/test_ip_scope.py`. **Live-verified
      2026-11-08** on Docker Desktop for Mac: `192.168.65.7` came out as
      `local` with the Docker Desktop hint, and the report's internet
      section listed only example.com.
- [x] **Fixed 2026-11-08: `analyze top-talkers` returned a row with
      `src_ip: null, dst_ip: null`.** Checked against real tshark output on
      a hand-built pcap: it was three bugs, not one. (1) ARP has no IP
      layer - expected, so `top_talkers()` now adds a `note` to that row and
      every row lists its `protocols`. (2) **All IPv6 packets** were stored
      with null addresses, because `enrich.FIELDS` only asked tshark for
      `ip.src`/`ip.dst`; it now also reads `ipv6.src`/`ipv6.dst`. (3) ICMP
      error packets quote the original IP header, so tshark returned
      `ip.src` as `"10.0.0.1,172.17.0.2"` and that was stored as one bogus
      address; `parse_pcap` now passes `-E occurrence=f`. Pcaps enriched
      before this fix keep their null IPv6 rows - re-run `enrich` on them
      into a fresh DB to fix. Tests: `tests/test_enrich.py` (one test runs
      real tshark, skipped if it isn't installed),
      `test_top_talkers_labels_non_ip_rows`. **Live-verified 2026-11-08** on
      Docker Desktop for Mac (alpine target + peer on an IPv6-enabled
      network, ping and ping -6): IPv6 rows carry addresses, ARP shows as
      one labelled row, no comma-joined addresses in `flows`. ICMP error
      rows still carry ports from the quoted inner header (e.g. 5555->53) -
      harmless, but not the ICMP packet's own ports.
- [x] **Fixed 2026-11-08 (surfaced by the IPv6 fix above):** with IPv6
      visible, the report named the container as `ff02::16` (multicast
      neighbour-discovery chatter outnumbered its own traffic) and said it
      sent 0 B. `report.build_report()` now uses the container's recorded
      `containers.ip_addresses` and counts sent/received across all of them
      (IPv4 and IPv6); the frequency guess is only a fallback and skips
      multicast and `::`/`0.0.0.0`. Live-verified the same day on the same
      capture: report lists `172.20.0.3` plus its two IPv6 addresses and
      shows 2.1 KB sent / 820 B received.

## report.py (plain-language summary) - known gaps

- [x] **Fixed 2026-11-08:** the report now uses `containers.ip_addresses`
      for "which IP is the container itself" (see the IPv6 entry above).
      The most-frequent-IP guess remains only for data with no recorded
      addresses, and can still misfire there for a container that talks to
      one peer far more than everything else.
- [ ] Sidecar mode (`nettap sidecar`) doesn't call the Docker API. Since
      2026-11-08 it records the target's own IPs from its interface, but it
      still knows nothing about *other* containers, so the
      container-to-container matrix can't name the peers a sidecar-watched
      container talks to. Consider having
      `sidecar` optionally accept `--docker-api` to still enrich this via
      docker.sock if it's mounted, for a more reliable report.
- [ ] Hostname resolution for external destinations only uses TLS SNI seen
      on that connection - plaintext HTTP (Host header) and DNS-answer-to-IP
      correlation aren't used yet, so some external IPs will show as bare
      IPs even though a hostname was knowable from the capture.
- [ ] No HTML/text escaping test for a container or hostname containing
      special characters beyond what test_report.py covers - worth a
      dedicated test if this ever takes attacker-influenced input seriously.

## Nice-to-haves noticed while building, not yet triaged

- [ ] `nettap attach`/`detach` currently take container name/ID *or* a label
      selector in the same command; consider splitting into clearer
      subcommands if this gets confusing in practice.
- [ ] `status` only reflects what the daemon last wrote to `live_sessions` -
      if the daemon dies uncleanly the table can go stale. Consider a
      heartbeat timestamp and having `status` flag stale rows.
- [ ] CLI output is JSON-only for `analyze`; a `--format table` option would
      make ad-hoc terminal use nicer.
