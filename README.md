# nettap

Attach traffic capture to one or many Docker containers, and analyze
docker-host, docker-docker, and docker-internet flows after the fact.

## How it sees the traffic

Every container gets its own network namespace wired to the host by a veth
pair (one end is the container's `eth0`, the other sits on the host attached
to a bridge). That host-side veth is the *only* door in or out of the
container, so capturing on it sees everything: traffic to the host, traffic
to other containers on the same bridge, and traffic out to the internet
(after NAT).

`nettap` resolves that host-side interface for a container without needing
anything installed inside the container image: it enters the container's
network namespace (via the netns file Docker already exposes under
`/var/run/docker/netns`) and reads the kernel's own record of which host
interface is its veth peer. Details and caveats are in
`nettap/discovery.py`'s docstring.

## Architecture

```
 docker events / desired-state table          per-container tcpdump          tshark        SQLite
 (controller.py, poll every 5s)         --->   (capture.py)             --->  (enrich.py) -> (storage.py)
        |                                              |
        v                                              v
  attach/detach requests from             raw pcaps, rotated every 60s
  `nettap attach/detach` CLI calls        in data/pcap/, kept as-is
```

- **controller.py** - a small reconciliation loop: figure out which
  containers *should* be captured (label selector + ad-hoc attach requests),
  diff against what's currently captured, attach/detach the difference.
- **capture.py** - runs one `tcpdump` per attached container against its
  resolved veth, rotating pcap files.
- **enrich.py** - parses each rotated pcap with `tshark` into flow-level rows
  (5-tuple, byte length, DNS query, TLS SNI).
- **storage.py** - SQLite: container metadata, flow rows, and the shared
  "desired state" / "live sessions" tables that let `nettap attach` from one
  terminal steer the `nettap watch` daemon running in another.
- **analyze.py** - read-side queries: top talkers, container-to-container
  traffic matrix, DNS lookups, protocol mix, and traffic that left the
  Docker network entirely.

## Quick start

```
docker compose up -d --build
```

By default the daemon watches for containers labeled `monitor=true`. Start
one:

```
docker run -d --name web --label monitor=true nginx
```

Within one poll cycle (5s) `nettap` attaches automatically. See
`examples/sample_queries.md` for a full walkthrough including ad-hoc
attach/detach and the `analyze` subcommands.

### Attaching to specific containers instead of a label

```
docker compose exec nettap nettap --data-dir /data attach web db
docker compose exec nettap nettap --data-dir /data detach web
docker compose exec nettap nettap --data-dir /data status
```

### Docker Desktop for Mac / Windows (host networking is unreliable there)

`watch` (above) needs the nettap container to run with `network_mode: host`
so it can see *other* containers' host-side veth interfaces. On Docker
Desktop for Mac/Windows that's an experimental, known-buggy feature (see
[docker/for-mac#7261](https://github.com/docker/for-mac/issues/7261)) - it
can silently fail to actually see the host network, even enabled. Don't rely
on it there.

Use **sidecar mode** instead: it makes the nettap container join one target
container's network namespace directly (`--network container:<target>`), a
completely ordinary and reliable Docker feature, and captures that shared
`eth0` - no host networking, no `nsenter`, no docker.sock mount needed at
all. One sidecar watches one container; run one per container you care
about.

```
docker build -t nettap .
mkdir -p data

docker run -d --name nettap-web \
  --network container:web \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$(pwd)/data:/data" \
  nettap sidecar --target web

docker exec nettap-web nettap --data-dir /data status
docker exec nettap-web nettap --data-dir /data analyze top-talkers --container web
docker exec nettap-web nettap --data-dir /data analyze external
docker exec nettap-web nettap --data-dir /data analyze dns --container web

docker stop nettap-web && docker rm nettap-web   # tear down when done
```

Raw pcaps land in `./data/pcap/` on the host either way (bind-mounted), so
`wireshark ./data/pcap/web_*.pcap` works for a deep dive regardless of which
capture mode produced them.

### Running without Docker Compose

```
pip install -e .
sudo nettap --data-dir ./data watch --label monitor=true
```

(needs `tcpdump`, `tshark`, `nsenter` on PATH, and root or the
`NET_ADMIN`/`NET_RAW`/`SYS_ADMIN` capabilities)

## Why the tool container needs `network_mode: host` + a few capabilities

Other containers' host-side veth interfaces live in the host's root network
namespace. A normally-networked container can't see them, so `nettap`'s own
container needs `network_mode: host`. It does **not** need `--privileged` or
`--pid=host`: `NET_ADMIN` + `NET_RAW` (for tcpdump) and `SYS_ADMIN` (to enter
another container's netns via `nsenter --net=<sandbox-key>`) are enough.

This is real privilege - only run it in environments you trust.

## Development

```
pip install -e ".[dev]"
pytest
```

Tests use mocked Docker/tcpdump/tshark calls (no real Docker daemon
required) and cover the veth-resolution logic, storage layer, and the
`analyze` queries. There is no integration test against a live Docker host
yet - see TODO.md, that's the first thing to run before trusting this in
production.

## Project layout

```
nettap/
  nettap/
    discovery.py   veth resolution (container -> host interface)
    capture.py     tcpdump process lifecycle per container
    controller.py  reconciliation loop (desired state -> attach/detach)
    enrich.py      pcap -> structured flow rows via tshark
    storage.py     SQLite schema + accessors
    analyze.py     read-side queries
    cli.py         `nettap` command line
  tests/           unit tests (mocked, no live Docker needed)
  examples/        sample CLI session
  Dockerfile, docker-compose.yml
  TODO.md          roadmap - read this before your next session
```

## Known limitations

- `--network host` containers are skipped (no dedicated veth to capture on).
- TLS/SSH traffic gives metadata (IPs, ports, byte counts, SNI) not
  plaintext payloads.
- Single Docker host only; Swarm/overlay cross-host correlation isn't done.
- No disk-usage cap on captured pcaps yet.

See `TODO.md` for the full list and what's next.
