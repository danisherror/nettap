#!/usr/bin/env bash
# End-to-end check of sidecar mode against a real Docker daemon.
#
# Starts a throwaway nginx server and an alpine client on their own network,
# puts a nettap sidecar on each (both writing to one data dir), sends HTTP
# from client to server and HTTPS to the internet, then enriches the pcaps
# and checks the SQLite flow store with nettap's own query functions.
#
# Usage: scripts/integration_test.sh [--no-internet] [--keep]
#   --no-internet  skip the HTTPS-to-example.com part and its checks
#   --keep         leave the data dir in place afterwards (for debugging)
#
# Uses sidecar mode, which works on Docker Desktop for Mac/Windows as well as
# Linux. `watch` mode needs a Linux host and isn't covered here (see TODO.md).
# Everything it creates is named nettap-it-<random> and removed on exit.
set -euo pipefail

INTERNET=1
KEEP=0
for arg in "$@"; do
    case "$arg" in
        --no-internet) INTERNET=0 ;;
        --keep) KEEP=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

cd "$(dirname "$0")/.."
P="nettap-it-$(printf "%04x%04x" $RANDOM $RANDOM)"
DATA="$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXX")"
IMAGE="$P-image"
NET="$P-net"
SRV="$P-srv"
CLI="$P-client"

cleanup() {
    docker rm -f "$SRV-sidecar" "$CLI-sidecar" "$SRV" "$CLI" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
    if [ "$KEEP" = 1 ]; then
        echo "data kept in $DATA"
    else
        rm -rf "$DATA"
    fi
}
trap cleanup EXIT

step() { echo "==> $*"; }

step "building nettap image"
docker build -q -t "$IMAGE" . >/dev/null

step "starting $SRV (nginx) and $CLI (alpine) on $NET"
docker network create "$NET" >/dev/null
docker run -d --name "$SRV" --network "$NET" nginx:alpine >/dev/null
docker run -d --name "$CLI" --network "$NET" alpine sleep 600 >/dev/null

step "starting a sidecar on each"
for target in "$SRV" "$CLI"; do
    docker run -d --name "$target-sidecar" --network "container:$target" \
        --cap-add NET_ADMIN --cap-add NET_RAW -v "$DATA:/data" \
        "$IMAGE" sidecar --target "$target" >/dev/null
done
# wait until both tcpdumps report they're listening
for target in "$SRV" "$CLI"; do
    for _ in $(seq 30); do
        docker logs "$target-sidecar" 2>&1 | grep -q "listening on" && break
        sleep 1
    done
    docker logs "$target-sidecar" 2>&1 | grep -q "listening on" \
        || { echo "sidecar for $target never started:"; docker logs "$target-sidecar"; exit 1; }
done

step "generating traffic"
for _ in 1 2 3; do
    docker exec "$CLI" wget -q -O /dev/null "http://$SRV/"
done
if [ "$INTERNET" = 1 ]; then
    docker exec "$CLI" wget -q -O /dev/null https://example.com/
fi
sleep 2

step "stopping sidecars (flushes the pcaps) and enriching"
docker stop "$SRV-sidecar" "$CLI-sidecar" >/dev/null
docker run --rm -v "$DATA:/data" "$IMAGE" enrich

step "checking the flow store"
# -i is required: without it docker doesn't pass the heredoc through, python
# runs an empty script and exits 0. The grep below guards against that too.
docker run -i --rm -v "$DATA:/data" -e SRV="$SRV" -e CLI="$CLI" -e INTERNET="$INTERNET" \
    --entrypoint python "$IMAGE" - <<'EOF' | tee "$DATA/checks.txt"
import json, os, sys
from nettap import analyze, report, storage

srv, cli, internet = os.environ["SRV"], os.environ["CLI"], os.environ["INTERNET"] == "1"
conn = storage.connect("/data/nettap.db")
failures = []


def check(ok, what):
    print(("  ok    " if ok else "  FAIL  ") + what)
    if not ok:
        failures.append(what)


def ips(name):
    row = conn.execute("SELECT ip_addresses FROM containers WHERE name = ?", (name,)).fetchone()
    return set(json.loads(row["ip_addresses"]).values()) if row else set()


def count(sql, *args):
    return conn.execute(sql, args).fetchone()[0]


srv_ips, cli_ips = ips(srv), ips(cli)
check(bool(srv_ips) and bool(cli_ips), f"both containers recorded their IPs ({srv_ips}, {cli_ips})")

for name in (srv, cli):
    check(count("SELECT COUNT(*) FROM flows WHERE container_name = ?", name) > 0,
          f"flow rows exist for {name}")

marks = lambda s: ",".join("?" * len(s))
check(count(f"SELECT COUNT(*) FROM flows WHERE container_name = ? AND dst_port = 80 "
            f"AND src_ip IN ({marks(cli_ips)}) AND dst_ip IN ({marks(srv_ips)})",
            cli, *cli_ips, *srv_ips) > 0,
      "client capture has client -> server HTTP (port 80)")
check(count(f"SELECT COUNT(*) FROM flows WHERE container_name = ? AND src_port = 80 "
            f"AND src_ip IN ({marks(srv_ips)}) AND dst_ip IN ({marks(cli_ips)})",
            srv, *srv_ips, *cli_ips) > 0,
      "server capture has server -> client HTTP replies")

pairs = {(r["src_container"], r["dst_container"]) for r in analyze.container_matrix(conn)}
check((cli, srv) in pairs and (srv, cli) in pairs, f"container matrix links both ways ({pairs})")

check(count("SELECT COUNT(*) FROM flows WHERE src_ip LIKE '%,%' OR dst_ip LIKE '%,%'") == 0,
      "no comma-joined addresses")

check(any(analyze.hostnames(conn, cli).get(ip, {}).get("hostname") == srv for ip in srv_ips),
      "server named from the client's HTTP Host header / DNS lookup")

if internet:
    internet_rows = analyze.external_destinations(conn, scope="internet")
    check(any(cli in (r["containers"] or "").split(",") for r in internet_rows),
          "client has internet destinations")
    check(all(r["dst_ip"] not in srv_ips | cli_ips for r in internet_rows),
          "no container's own IP listed as an internet destination")
    check(count("SELECT COUNT(*) FROM flows WHERE container_name = ? AND tls_sni = 'example.com'",
                cli) > 0, "TLS SNI example.com recorded")
    # No DNS check: on this user-defined network lookups go to Docker's
    # embedded DNS at 127.0.0.11 over lo, never eth0 (see TODO.md).

data = report.build_report(conn, cli)
check(set(data["self_ips"]) == cli_ips, f"report identifies the client by its own IPs ({data['self_ips']})")
check(data["sent_bytes"] > 0 and data["received_bytes"] > 0, "report shows bytes sent and received")
check(any(srv in (p["src_container"], p["dst_container"]) for p in data["container_peers"]),
      "report lists the server as a peer container")
check(srv in report.render_text(data), "text report names the server")

print()
if failures:
    print(f"{len(failures)} check(s) failed")
    sys.exit(1)
print("all checks passed")
EOF
grep -q "^all checks passed$" "$DATA/checks.txt" || { echo "checks did not all pass"; exit 1; }
