# TODO / Roadmap

**Status:** MVP is functionally complete - polling controller, per-container
veth capture via tcpdump, tshark-based enrichment into SQLite, CLI for
attach/detach/status/analyze. It was built and unit-tested (mocked
Docker/tcpdump/tshark - the sandbox this was built in has no Docker daemon,
tcpdump, or tshark installed) but **has not been run against a real Docker
host yet**. Treat it as code-reviewed, not integration-tested. The very first
thing to do next session is the P0 list below.

## P0 - verify the MVP actually works

- [x] Confirmed (via docs.docker.com and
      [docker/for-mac#7261](https://github.com/docker/for-mac/issues/7261))
      that `network_mode: host` - what `watch`/docker-compose.yml relies on -
      is an unreliable, known-buggy beta feature on Docker Desktop for
      Mac/Windows, including Apple Silicon. Added `nettap sidecar` as the
      Mac/Windows-native alternative (joins the target's netns via
      `--network container:<target>` instead of needing host networking at
      all - see README's "Docker Desktop for Mac / Windows" section). Still
      only smoke-tested via `--help` and unit tests here (no tcpdump/Docker
      daemon in the sandbox this was built in) - **run it against your
      actual container next** and confirm packets actually show up in
      `analyze`.
- [ ] Run `docker compose up --build` (`watch` mode) on a real *Linux* Docker
      host (not Docker Desktop) and confirm veth resolution, capture start,
      and enrichment all work end-to-end - this is the only place
      `network_mode: host` is expected to work properly.
- [ ] Run `nettap sidecar` (see README) against a real container on Docker
      Desktop for Mac/Windows and confirm packets land in the pcap and in
      `analyze` output - this is the path most users on a dev machine will
      actually take, so it deserves the most testing attention.
- [ ] Confirm the SandboxKey-based `nsenter` trick works on the target Docker
      version/storage driver (logic was reasoned through and unit-tested with
      mocks, not exercised against a live netns).
- [ ] Add an integration test script (`scripts/integration_test.sh`) that
      spins up two throwaway containers, attaches, generates traffic between
      them and to the internet, and asserts flow rows land in SQLite
      correctly.
- [ ] Verify tshark's default dissectors are available in the slim Docker
      image (some protocol dissectors ship as separate packages) - trim
      `enrich.FIELDS` / the Dockerfile's apt list as needed.

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
- [ ] tcpdump processes are children of the `nettap watch` process; if that
      process is killed with SIGKILL (not SIGTERM) the capture children are
      orphaned and keep running. Either reap orphans on daemon startup, or
      run tcpdump in its own process group and kill the group.
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

## report.py (plain-language summary) - known gaps

- [ ] The "which IP is the container itself" heuristic in `report._self_ip`
      (most-frequent IP across src/dst) will misfire for a container that
      talks to one single peer overwhelmingly more than everything else
      combined - worth cross-checking against `containers.ip_addresses` when
      that's populated (it isn't yet in sidecar mode - see below).
- [ ] Sidecar mode (`nettap sidecar`) doesn't call the Docker API, so
      `containers.ip_addresses` is never populated for that container - the
      container-to-container matrix and "self IP" heuristic both work purely
      from observed traffic instead of known ground truth. Consider having
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
