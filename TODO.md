# TODO / Roadmap

**Status:** MVP is functionally complete - polling controller, per-container
veth capture via tcpdump, tshark-based enrichment into SQLite, CLI for
attach/detach/status/analyze/report. All 159 unit tests pass.

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
- [x] **Fixed 2026-11-08: the SandboxKey-based `nsenter` trick resolved
      every container to the host's `eth0`.** Live test first (Docker
      Desktop for Mac, nettap image with the compose file's caps/mounts):
      `resolve_veth()` returned `eth0` for a bridge, a macvlan and an ipvlan
      container. Cause: `nsenter --net` + `cat /sys/class/net/eth0/iflink`
      reads the *host's* sysfs (sysfs shows the namespace that mounted it -
      same MAC as the host's eth0, host interface list), so it got the host
      eth0's own ifindex. `ip netns exec` remounts /sys for this reason
      (netns_switch() in
      [iproute2 lib/namespace.c](https://github.com/iproute2/iproute2/blob/main/lib/namespace.c)).
      `watch` would have captured the whole host's traffic per container.
      Now `discovery.resolve_capture()` asks netlink inside the netns
      (`nsenter ... ip -j -d link show dev eth0`: ifindex, link kind,
      link_index) and only accepts a host interface whose iflink points back
      at the container's eth0. Live test after: the bridge container
      resolved to its real veth (`vethb56415c`, on its `br-*`).
- [x] **Fixed 2026-11-08: `watch` couldn't enter containers started after
      it.** With `/var/run/docker/netns` bind-mounted `:ro` (Docker's
      default propagation is `rprivate`), their netns files show up as
      empty files and `nsenter` fails with "Invalid argument" - seen live,
      only pre-existing containers attached. `docker-compose.yml` now
      mounts it `:ro,rslave`, and nettap logs a hint naming the fix when
      it hits that error. Docker Desktop refuses `rslave` ("not a shared or
      slave mount"; "Mount propagation doesn't work with Docker Desktop",
      [docs](https://docs.docker.com/engine/storage/bind-mounts/#configure-bind-propagation)),
      so `rslave` itself is **untested** - needs the Linux host above.
- [x] **Done 2026-11-08 for `sidecar` mode:** `scripts/integration_test.sh`
      starts a throwaway nginx server + alpine client on their own network,
      a sidecar on each sharing one data dir, sends HTTP client->server and
      HTTPS to example.com, enriches, and checks the flow store with
      nettap's own query functions (14 checks at first, 19 since the
      DNS checks were added: both containers' IPs
      recorded, HTTP seen in both captures, container matrix links both
      ways, no comma-joined IPs, internet destinations + SNI, no
      container's own IP counted as internet, report self-IPs/bytes/peers).
      `--no-internet` skips the internet checks (14 left; 11 before the DNS checks). Passed on Docker
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
      skipped entirely in `watch` (no dedicated veth exists to capture on).
      `sidecar --attribute-by-port` covers them by port (see below); still
      open: the same for `watch`, short connections (eBPF/cgroup
      attribution would catch every packet), traffic with other containers
      on the host (only `eth0` is captured), and ICMP.
- [x] **Done 2026-11-08: `sidecar --attribute-by-port` for `--network host`
      targets.** Needs `--pid container:<target>` and `--cap-add
      SYS_PTRACE`. Live check first: with the shared PID namespace the
      sidecar sees the target's processes and their sockets, but reading
      the fds of nginx's workers (user nginx) gave EACCES until SYS_PTRACE
      was added ([proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html):
      a ptrace access check). New `hostports.py`: a thread samples the
      target's TCP/UDP ports every 0.25s (every process except the
      sidecar's own tree; inodes from `/proc/<pid>/fd` matched against
      `/proc/net/{tcp,tcp6,udp,udp6}`) into a new `owned_ports` table as
      time intervals, and enrichment keeps only packets whose host-side
      address and port the target held then (2s slack). The container row
      gets `capture_scope = 'ports'`; the report adds a note about what such
      a capture can miss. The sidecar refuses to start without visible
      target processes or with unreadable ones. Live test (Docker Desktop
      for Mac, nginx `--network host`): of 927 packets in the raw `eth0`
      pcaps, 11 were kept - exactly the target's ~4s connection to
      example.com (`owned_ports` had tcp/80 and that connection's port).
      Another container's 3 NATed requests to example.com and Docker
      Desktop's internal HTTP were dropped. The target's quick `wget` and
      its DNS lookup were missed, as expected. Tests: 10 new in
      `tests/test_hostports.py` (fake `/proc`), also run inside the image.
- [x] **Fixed 2026-11-08: a sidecar on a `--network host` target captured
      the whole Docker host and labelled it all as the target.** Live test
      first (Docker Desktop for Mac, sidecar joined to an alpine
      `--network host` container): it captured on the VM's `eth0`, and
      another container's 3 requests to example.com (NATed to the VM's
      192.168.65.3) plus ~110 packets of Docker Desktop's internal HTTP
      (192.168.65.1 <-> .7) were all stored as the target's - 444 rows.
      The host namespace held `docker0` and two `br-*` bridges; a
      bridge-network container's held none. The sidecar now checks for
      bridge interfaces (`discovery.bridge_interfaces()`, no docker.sock
      needed) and exits 1 with an explanation; `--allow-host-network`
      captures anyway with a warning (Docker-in-Docker targets have their
      own bridges). Tests: 4 new, plus an autouse fixture so the sidecar
      tests don't trip over a real `docker0` when run on a Linux host.
      Live test after: refused the host-network target, started with the
      flag (warning logged), and started normally on a bridge-network
      target. Integration test not re-run (bridge targets only, unchanged
      path; the bridge-target live check covers it).
- [ ] macvlan/ipvlan network drivers: same problem as host networking - no
      standard veth-to-bridge topology. Needs investigation.
- [ ] Swarm/overlay networks: traffic between containers on different hosts
      travels over a VXLAN tunnel. Capturing on the local veth still sees it,
      but cross-host correlation (matching flows between two hosts' nettap
      instances) isn't implemented - each host is currently an independent
      island.
- [x] **Partly fixed 2026-11-08: `container_matrix()` missed traffic
      through a published host port** (it only matched dst_ip against
      container addresses). Live test first (Docker Desktop for Mac,
      sidecars with `--docker-api`, server `-p 18080:80` on one network,
      client on another, `wget http://host.docker.internal:18080/`): the
      client's capture shows `192.168.65.254:18080`, the server's shows
      the request coming from `192.168.65.1` on a random port - a proxy in
      between, so there's no port pair for conntrack-style matching even
      in principle. Now `containers.published_ports` stores each
      container's host-port bindings from the Docker API
      (`NetworkSettings.Ports`), and a flow to a *local* (non-internet),
      non-container address on a host port exactly one container
      publishes is counted as that container's traffic: matrix rows gained
      `via` ("direct" / "published port") and `container_peers()` (the
      report) includes it. Live test after: matrix `cli -> srv 506 B, 6
      packets, published port`, report lists srv under "Other
      containers". Open: (1) only the client side is matched - the
      server's capture still shows the proxy address as an unknown local
      destination; on a Linux host conntrack could link the two; (2)
      **fixed 2026-11-08, see next item**; (3) ports are only known with
      `--docker-api` or in `watch` mode (a sidecar's own target's ports:
      **fixed 2026-11-08, see below**); (4) TCP vs UDP: **fixed
      2026-11-08, see below**; (5) not tried on Linux, where the client would hit the
      host's address or the bridge gateway instead.
- [x] **Fixed 2026-11-08: published-port traffic was counted twice in the
      client's report, and every report's internet/local byte counts
      included other containers' traffic.** The report listed the same
      bytes under the peer container and under local addresses
      (192.168.65.254). Separately, `external_destinations()` summed bytes
      per address across all containers and the report only filtered which
      rows to show, so two containers reaching the same address each showed
      the combined total. `external_destinations()` now takes `container`
      (also `analyze external --container`), counts only that capture and
      names hosts from it, and leaves out flows `_published_port_flows()`
      already attributes to a container. Tests in `test_analyze.py` /
      `test_report.py` (4 failed before the fix). Live test (Docker Desktop
      for Mac, same setup as above plus a request to neverssl.com): the
      client report no longer lists 192.168.65.254 and shows srv with 1.5
      KB sent, matching the raw flows (1518 B to port 18080); the shared
      `ff02::16` row shows the client's 1.0 KB instead of both containers'
      2.1 KB.
- [x] **Fixed 2026-11-08: a sidecar never recorded its own target's
      published ports**, so a peer reaching the target through one was only
      matched if *another* sidecar ran with `--docker-api`. With
      `--docker-api` the sidecar now finds its target in the API (the
      container holding the shared interface's IP,
      `discovery.split_by_netns()`) and stores its ports on its own row,
      keeping the `--target` name and interface IPs. That surfaced two
      problems when the label differs from the real name and another
      sidecar's `--docker-api` stores the real name too: (a) both names
      claimed the port, so it was dropped as ambiguous - names that share an
      address now count as one owner, named after the one with a capture;
      (b) the container's own replies matched its other name, so the matrix
      showed it talking to itself - `container_matrix()`/`container_peers()`
      now skip addresses the captured container holds itself. Tests: 3 new,
      all failed before. Live test (Docker Desktop for Mac, server `-p
      18080:80` with a sidecar labelled `srvlabel`, client on another
      network, both `--docker-api`): `srvlabel`'s row holds port 18080, the
      matrix has one row `cli -> srvlabel 1.5 KB, published port` and no
      self rows, and the client's report names `srvlabel` as its peer.
- [x] **Fixed 2026-11-08: the published-port match ignored TCP vs UDP.**
      `flows.protocol` is the top layer (HTTP, DNS...), so the transport
      wasn't stored at all. enrich now reads tshark's `frame.protocols` and
      stores the first transport layer in new `flows.transport`
      (tcp/udp/sctp/icmp/icmpv6; added to existing databases on connect).
      An ICMP error quoting a UDP header is `ip:icmp:ip:udp`, so it's stored
      as `icmp` - its ports come from the quoted header and no longer match
      a published port. Ports are now owned per (port, protocol), so one
      host port published as TCP by one container and UDP by another is
      attributed to each instead of being dropped as ambiguous. Flows
      enriched before this have no transport and match on the port alone
      (only if one container owns every protocol on it). Tests: 6 failed
      before (incl. the real-tshark test). Live test (Docker Desktop for
      Mac, client sidecar with `--docker-api`; nginx `-p 18080:80/tcp`,
      alpine `nc -lu` `-p 18080:5000/udp`, client sends HTTP and UDP to
      host.docker.internal:18080): matrix shows cli -> tcp server 1012 B
      sent and cli -> udp server 156 B; the report's per-peer totals
      (4.0 KB / 156 B) match the raw flows by transport.
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
- [x] **Fixed 2026-11-08: no disk-usage cap on `data/pcap/`.** `watch` and
      `sidecar` take `--pcap-max-age-hours` and `--pcap-max-size-mb` (both
      off by default). Every 30s `purge_pcaps()` deletes the oldest pcaps
      (by mtime) in the whole directory until both limits hold. The newest
      file of each capture is never deleted, since tcpdump may still be
      writing it - including captures from another sidecar sharing the data
      dir - so the cap can be exceeded by up to one file per capture, plus
      whatever is written between sweeps. Live test (sidecar, 5s rotation,
      0.02 MB cap, target pinging 1.1.1.1): the directory grew to ~56 KB
      between sweeps and dropped back to ~15 KB at each sweep; tcpdump kept
      writing and enrichment kept running (967 flow rows). Known
      limitations: a file is deleted whether or not it has been enriched
      yet (only a risk with a very small size cap), and the last file of a
      capture that has stopped is kept forever.
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
- [x] **Fixed 2026-11-08: a sidecar got stuck when its target stopped or
      was recreated.** The old note here guessed tcpdump would keep running
      on an orphaned namespace. A live test showed something different:
      when the target stops (plain `docker stop` is enough) or is removed,
      Docker deletes `eth0` from the shared namespace. tcpdump then exited
      with "eth0: No such device exists", and `restart_dead()` restarted it
      every second forever, spamming the log while the sidecar still
      showed as running. Starting the target again gives it a new namespace
      without `eth0` in the sidecar's. Now the sidecar checks
      `/sys/class/net/<iface>` each second and exits with code 3 and a clear
      error when it's gone, and refuses to start without it. Live-tested:
      after `docker stop` of the target the sidecar exited 3 within a
      second; after `docker start` of the target, `docker start` of the
      sidecar resumed capture (new pcaps written). `--restart
      unless-stopped` does not recover it: Docker retried once while the
      target was down ("cannot join network namespace of a non running
      container") and gave up. A removed target still needs a new sidecar.
      Following the target automatically would need docker.sock (see the
      `--docker-api` idea below).

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
- [x] **Done 2026-11-08: a sidecar couldn't name peers without their own
      sidecar.** It only knew its target's IPs. `sidecar --docker-api` (needs
      docker.sock mounted; refuses to start if it can't reach the API) now
      records every other running container's name and IPs on start and
      every 30s, via `discovery.other_containers()`. That skips the target
      itself (any IP shared with the sidecar's interface - otherwise a
      `--target` label that differs from the real name made the target its
      own peer) and containers without an IP (other sidecars), and doesn't
      try to resolve veths (`inspect_container(resolve=False)`). API errors
      after startup are logged and capture carries on. Live test (Docker
      Desktop for Mac): nginx server without a sidecar, alpine client with
      a `--docker-api` sidecar labelled `dapi-client` (real name
      `nettap-dapi-client`). The report listed `nettap-dapi-srv` as the one
      peer (561 B sent / 1.5 KB received); the containers table held only
      the sidecar's own row and the server. IPv6 from the API: **fixed
      2026-11-08, see next item**.
- [x] **Fixed 2026-11-08: only IPv4 addresses were read from the Docker
      API** (`IPAddress`, not `GlobalIPv6Address`) - in `watch` and in
      `sidecar --docker-api` - so a peer reached over IPv6 showed up as an
      unknown local address instead of by name. New
      `discovery.network_ips()` also stores each network's IPv6 address,
      under `<network>/inet6` (the sidecar's own `interface_ips()` uses the
      same `/inet6` style). Link-local addresses aren't in the API, so a
      peer reached only via `fe80::` still isn't named. Tests: 2 new, both
      failed before. Live test (Docker Desktop for Mac, `docker network
      create --ipv6`, nginx without a sidecar, alpine client with a
      `--docker-api` sidecar, `wget http://[<server IPv6>]/`): the server's
      row holds `fdac:b22d:f5d5::2`, all 39 flows (6.9 KB) to it count as
      that peer in the report, and the address no longer appears under
      local addresses. `watch` uses the same function but wasn't run live.
- [x] **Fixed 2026-11-08: traffic from a container that then went quiet
      wasn't reported until its next packet.** In the `--docker-api` live
      test (10s rotation) the first file stayed open for over 2 minutes
      after the last request. tcpdump's `-G` only checks the time when a
      packet arrives, and writes that packet to the new file
      (`dump_packet_and_trunc()` in
      [tcpdump.c](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.c)),
      so a file is complete once the interval since the time in its name
      has passed. New `capture.finished_pcaps()` counts the newest file as
      done from then on (+2s slack), and the enrich loop uses it - no
      tcpdump restart, no lost packets. Live test (sidecar, 5s rotation):
      one HTTP request, then silence; the DNS capture never rotated again,
      but its file was enriched 7s after the request.
- [x] **Fixed 2026-11-08: a restarted sidecar/daemon stored every old pcap's
      flows again.** The enrich loop only remembered parsed files in
      memory and `flows` has no unique key, so after `docker restart` (which
      the README tells you to do after the target restarts) every report
      counted the old traffic twice. Live test before the fix: 51 rows ->
      118 after a restart, HTTP rows 4 -> 8. The loop now checks the DB
      first (`storage.pcap_enriched()`, new index on `flows.pcap_file`).
      `nettap enrich` also stopped parsing files a running daemon is still
      writing, which would now leave the rest of such a file unread:
      `live_sessions` gained `rotate_seconds`, and files of non-stale
      sessions that aren't finished are skipped. Live test after the fix:
      17 rows before a restart, 21 after (4 new ARP rows), no duplicate
      rows, and `nettap enrich` inserted 0.
- [x] **Fixed 2026-11-08: with `--docker-api`, traffic between containers
      was counted twice.** Each sidecar stores its target under the
      target's name, and the other sidecar's `--docker-api` stores the
      same container under its real ID, so `containers` had two rows per
      container and `container_matrix()`/`container_peers()` counted each
      flow once per row (100 bytes showed as 200). Both now join on a
      deduplicated (name, address) list. Live test (two sidecars with
      `--docker-api`, one HTTP request): 4 container rows, and the matrix
      matched the raw flows (client->server 559 B / 7 packets). A recreated
      container reusing an old address under another name: **fixed
      2026-11-08, see next item**.
- [x] **Fixed 2026-11-08: a container recreated under a different name at
      an old address got all of that address's traffic - and so did the old
      name.** Live repro first (Docker Desktop for Mac, fixed `--ip` on a
      user-defined network, client sidecar with `--docker-api`, 1 request to
      `old-db`, remove it, start `new-db` at the same IP, 3 requests): the
      report listed both names with the full 8.0 KB. Now `containers`
      stores each container's start time (`State.StartedAt`, new
      `started_at` column; a sidecar with `--docker-api` stores its
      target's), and `container_matrix()`/`container_peers()` give each
      flow to the one name that held the address at the flow's time - the
      latest start at or before it (Docker doesn't give one address to two
      running containers). Without a start time the row's `first_seen` is
      used. Two names of one container (sidecar label + real name) count
      once, under the name with its own capture, when their start times are
      equal - i.e. when the label's sidecar has `--docker-api`; without it
      a peer's traffic can still be split between the two names around the
      sidecar's start. Live test after: `old-db` 2.0 KB, `new-db` 6.0 KB.
      The first version used a correlated subquery that SQLite 3.54
      (macOS) accepts but 3.46 (the Docker image) rejects ("no such column:
      f.ts"), so it's now a join + `ROW_NUMBER()`, and the unit tests were
      also run inside the image. Tests: 5 new, all failed before.
      Integration test passes.
- [x] **Fixed 2026-11-08: external IPs were only named from TLS SNI.**
      enrich.py now also stores DNS answer addresses (`dns.a`/`dns.aaaa`,
      new `flows.dns_answers` column, JSON list) and the HTTP `Host` header
      (`flows.http_host`); existing databases get the columns on connect.
      tshark now runs with `-E occurrence=a -E aggregator=|` and every other
      field keeps only its first value, so the ICMP inner-header fix still
      holds. `analyze.hostnames()` picks a name per IP - TLS SNI, then HTTP
      Host, then DNS answer, most frequent within each - and both
      `analyze external` (new `hostname`/`hostname_source` fields) and the
      report use it. Live test (sidecar, default bridge): github.com named
      from SNI, neverssl.com from the Host header, and one.one.one.one -
      only pinged, never connected to over TLS/HTTP - from its DNS answer.
      Integration test gained a check that the server is named from the
      client's HTTP traffic; passes.
- [x] **Fixed 2026-11-08: DNS answers were invisible on user-defined
      networks (incl. every Compose network).** Containers there resolve
      through Docker's embedded DNS server at `127.0.0.11`
      ([Docker docs](https://docs.docker.com/engine/network/#dns-services)),
      which they reach over `lo`. Live test 2026-11-08: a sidecar on `eth0`
      saw no DNS packets at all, while one on `lo` saw the queries and
      answers (127.0.0.1 <-> 127.0.0.11). On the default bridge DNS goes out
      over `eth0`. `CaptureManager` now runs a second tcpdump per container
      on `lo` with the filter `host 127.0.0.11` (a port filter won't work:
      the embedded server's port is NATed from 53 to a random one; `-i any`
      would add the app's own localhost traffic and see each loopback packet
      twice), writing `<name>_<ts>.dns.pcap`. `sidecar` runs it directly
      (it shares the target's netns); `watch` runs it through
      `nsenter --net=<SandboxKey>`. The enrich loop, `nettap enrich` and
      pcap retention handle these files; the enrich loop's and `enrich`'s
      file matching also stopped picking up other captures whose name
      starts the same (`web_*.pcap` matched `web_2_*.pcap`). The report
      labels 127.0.0.11 and loopback addresses. Live test (sidecar, the
      integration test's user-defined network): the client's lookups of
      the server and of example.com, with answers, are recorded; the
      integration test now checks this (19 checks, all pass).
- [ ] The `lo` DNS capture in `watch` mode (via `nsenter`) is untested -
      needs the Linux host from P0.
- [x] **Fixed 2026-11-08: the `lo` DNS capture's pid wasn't stored in
      `live_sessions`**, so `reap_orphans()` couldn't clean it up after an
      unclean exit. `live_sessions` gained `dns_pid`/`dns_pcap_pattern`
      (added to existing databases on connect), `watch` and `sidecar`
      save both tcpdumps via `storage.save_capture_session()`, a DNS-only
      restart updates the row too, and `reap_orphans()` checks each pid
      against its own pattern. Live check (sidecar): the row's `pid` and
      `dns_pid` matched the running `tcpdump -i eth0` and
      `tcpdump -i lo ... host 127.0.0.11`. Reaping itself is unit-tested
      only - on Linux the parent-death signal stops both tcpdumps first.
- [x] **Fixed 2026-11-08: the report listed a peer container twice**
      under "Other containers" (seen in that day's integration run). It
      used `container_matrix()`, which has one row per capture and
      direction, so it showed web->db from web's capture and db->web from
      db's capture - and a peer without its own capture only showed one
      direction. New `analyze.container_peers()` counts one row per peer
      from the container's own capture, with sent/received bytes, and the
      report shows those. Integration test now requires exactly one peer
      row with traffic both ways; passes (client: server, 1.6 KB sent /
      4.6 KB received).
- [x] **Fixed 2026-11-08: the text report printed control characters from
      captured traffic as-is.** Hostnames come from TLS SNI, HTTP Host and
      DNS, so anything on the network can choose them. Checked with a
      hand-built pcap: tshark passes a raw ESC (`\x1b`) in an HTTP Host
      header straight through into `flows.http_host` (it only escapes some
      bytes, e.g. BEL becomes `\a`), so `nettap report` would have sent a
      live terminal escape sequence. DNS names arrive already escaped by
      tshark. Both renderers now show category-C characters (control,
      newline, bidi overrides, ...) as `\xNN`/`\uNNNN`; HTML was already
      `html.escape`d everywhere. New tests feed a hostile string through
      every string field of both renderers. Side note: tshark's `quote=d`
      output doubles backslashes, so that DNS name shows as `ev\\033[2Jil.com`
      - harmless, just ugly.

## Nice-to-haves noticed while building, not yet triaged

- [ ] `nettap attach`/`detach` currently take container name/ID *or* a label
      selector in the same command; consider splitting into clearer
      subcommands if this gets confusing in practice.
- [x] **Fixed 2026-11-08: `status` couldn't tell a dead daemon's rows from
      live ones.** `watch` (every poll, even if the Docker API call fails)
      and `sidecar` (every 5s) now refresh `live_sessions.updated_at` and
      record the interval in a new `heartbeat_interval` column (added to
      existing databases on connect). `status` marks a row STALE once it's
      more than 3 intervals + 10s old. Live test (sidecar): heartbeat age
      stayed under 5s while running and `status` showed no flag; after
      `docker kill` of the sidecar, `status` from a fresh container showed
      `STALE: no heartbeat for 35s`.
- [x] **Done 2026-11-08: `analyze` was JSON-only.** Every `analyze`
      subcommand now takes `--format json|table` (JSON stays the default,
      so scripts are unaffected). `utils.format_table()` takes the column
      list from the rows (rows can differ - only local destinations have a
      `hint`), shows byte columns human-readable, right-aligns numbers,
      cuts cells at 60 characters, and escapes control characters like the
      report does (`printable()`/`format_bytes()` moved from report.py to
      utils.py for this). Unit-tested through the CLI only; output is
      plain text with no Docker-specific behaviour to verify live.
