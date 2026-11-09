# Changelog

All notable changes to nettap are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0.0,
a minor version (0.x.0) may change the command line or the SQLite schema.

To release, see "Releasing" in `README.md`.

## [0.1.0] - Unreleased

First release.

### Added

- `nettap sidecar`: capture one container from inside its network
  namespace (`--network container:<target>`). Works on Linux and Docker
  Desktop (Mac, Windows); needs no host networking and no docker.sock.
- `nettap watch`: capture every container matching a label, plus ones added
  with `nettap attach`, on its host-side veth (Linux only, not yet verified
  on a real Linux host). macvlan, ipvlan, Swarm overlay and multi-network
  containers are captured inside their namespace; `--network host`
  containers by the ports they hold.
- `nettap sidecars`: keep one sidecar per labelled container, started
  again or recreated when its target restarts or is recreated.
- `nettap inspect <image>`: run an image inside a capture from its first
  packet and report everything it contacted.
- `nettap check`: compare a container's destinations with an allowlist
  (container names, hostnames, CIDRs) and exit non-zero on anything else,
  for use as a CI gate.
- `nettap report` (text or self-contained HTML), with `--compare` for what
  changed between two runs or two time ranges.
- `nettap analyze` (top talkers, container matrix, DNS, protocols, external
  traffic) as JSON or `--format table`.
- `nettap export`: flows as JSON or CSV, packets as one merged pcap.
- Traffic is parsed with tshark while tcpdump writes it, so it shows up
  within seconds. External addresses are named from TLS SNI, HTTP Host and
  DNS answers, including lookups to Docker's embedded DNS server.
- Raw pcaps are kept for 24 hours / up to 1 GB by default.
- Startup checks with one-line fixes (capabilities, docker.sock, data dir).
- `nettap --version`.
- Releases: the package on PyPI and a multi-arch image
  (`linux/amd64`, `linux/arm64`) at `ghcr.io/danisherror/nettap`, both
  built by CI from a version tag. Outside a container, `inspect` and
  `sidecars` use the published image of the installed version (pulled if
  needed) unless `NETTAP_IMAGE` or `--nettap-image` / `--image` is given.

[0.1.0]: https://github.com/danisherror/nettap/releases/tag/v0.1.0
