#!/usr/bin/env bash
# End-to-end check of nettap against a real Docker daemon.
#
# Starts a throwaway nginx server and an alpine client on their own network,
# captures both, sends HTTP from client to server and HTTPS to the internet,
# then enriches the pcaps and checks the SQLite flow store with nettap's own
# query functions.
#
# Usage: scripts/integration_test.sh [--mode sidecar|watch] [--no-internet] [--keep]
#   --mode sidecar  (default) one nettap sidecar per container, sharing its
#                   network namespace. Works on Docker Desktop and Linux.
#   --mode watch    one `nettap watch` daemon with host networking, set up
#                   like docker-compose.yml. Started before the containers, it
#                   picks up the server by label and the client via
#                   `nettap attach`. Needs a Linux Docker host.
#   --mode sidecars one `nettap sidecars` supervisor (docker.sock only), which
#                   starts a sidecar per labelled container. Before the
#                   traffic checks, the server is restarted and then
#                   recreated, and capture must resume both times with no
#                   manual step. Works on Docker Desktop and Linux.
#   --no-internet   skip the HTTPS-to-example.com part and its checks
#   --keep          leave the data dir in place afterwards (for debugging)
#
# Everything it creates is named nettap-it-<random> and removed on exit.
set -euo pipefail

MODE=sidecar
INTERNET=1
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="${2:-}"; shift ;;
        --mode=*) MODE="${1#--mode=}" ;;
        --no-internet) INTERNET=0 ;;
        --keep) KEEP=1 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
case "$MODE" in
    sidecar|watch|sidecars) ;;
    *) echo "--mode must be sidecar, watch or sidecars, got '$MODE'" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."
P="nettap-it-$(printf "%04x%04x" $RANDOM $RANDOM)"
DATA="$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")"
IMAGE="$P-image"
NET="$P-net"
SRV="$P-srv"
CLI="$P-client"
NETTAP="$P-nettap"   # the watch daemon or sidecar supervisor

cleanup() {
    docker rm -f "$NETTAP" "$SRV-sidecar" "$CLI-sidecar" "nettap-sidecar-$SRV" \
        "nettap-sidecar-$CLI" "$SRV" "$CLI" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [ "$KEEP" = 1 ]; then
        echo "data kept in $DATA"
    else
        # nettap runs as root, so on a Linux host the files it wrote are
        # root-owned and a plain rm fails. Delete them from a container first.
        docker run --rm -v "$DATA:/data" --entrypoint sh "$IMAGE" \
            -c 'rm -rf /data/* /data/.[!.]*' >/dev/null 2>&1 || true
        rm -rf "$DATA" || echo "could not remove $DATA" >&2
    fi
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step() { echo "==> $*"; }

# wait_until <what> <command...>: run the command each second, fail after 30s
wait_until() {
    local what="$1"; shift
    for _ in $(seq 30); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "$what never happened"
    docker ps -a --filter "name=$P" --filter "name=nettap-sidecar-$P"
    [ "$MODE" = sidecars ] && docker logs "$NETTAP"
    exit 1
}

# sidecar_up <target>: the supervisor's sidecar for target runs, belongs to
# the target's current container, started after it, and tcpdump is listening
sidecar_up() {
    local sc="nettap-sidecar-$1" tid tstart
    tid=$(docker inspect -f '{{.Id}}' "$1") || return 1
    tstart=$(docker inspect -f '{{.State.StartedAt}}' "$1") || return 1
    [ "$(docker inspect -f '{{.State.Running}} {{index .Config.Labels "nettap.sidecar.target-id"}}' "$sc")" = "true $tid" ] || return 1
    [[ "$(docker inspect -f '{{.State.StartedAt}}' "$sc")" > "$tstart" ]] || return 1
    docker logs --since "$tstart" "$sc" 2>&1 | grep -q "listening on eth0"
}

# wait_for_log <container> <grep -E pattern> <what>: fail after 30s
wait_for_log() {
    for _ in $(seq 30); do
        docker logs "$1" 2>&1 | grep -Eq "$2" && return 0
        sleep 1
    done
    echo "$3 never happened. docker logs $1:"
    docker logs "$1"
    exit 1
}

step "building nettap image"
docker build -q -t "$IMAGE" . >/dev/null

docker network create "$NET" >/dev/null

if [ "$MODE" = watch ]; then
    # Same settings as docker-compose.yml. Started before the containers it
    # captures, so their netns files only reach it through the rslave mount.
    step "starting nettap watch (label $P=1)"
    docker run -d --name "$NETTAP" --network host --cgroupns host \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        -v /var/run/docker.sock:/var/run/docker.sock:ro \
        -v /var/run/docker/netns:/var/run/docker/netns:ro,rslave \
        -v "$DATA:/data" \
        "$IMAGE" watch --label "$P=1" --poll-interval 1 >/dev/null
    wait_for_log "$NETTAP" "nettap watching" "nettap watch starting"
fi
if [ "$MODE" = sidecars ]; then
    step "starting nettap sidecars (label $P=1)"
    docker run -d --name "$NETTAP" \
        -v /var/run/docker.sock:/var/run/docker.sock -v "$DATA:/data" \
        "$IMAGE" sidecars --label "$P=1" --poll-interval 1 >/dev/null
    wait_for_log "$NETTAP" "nettap supervising" "nettap sidecars starting"
fi

step "starting $SRV (nginx) and $CLI (alpine) on $NET"
docker run -d --name "$SRV" --network "$NET" --label "$P=1" nginx:alpine >/dev/null
CLI_LABEL=()
[ "$MODE" = sidecars ] && CLI_LABEL=(--label "$P=1")
docker run -d --name "$CLI" --network "$NET" ${CLI_LABEL[@]+"${CLI_LABEL[@]}"} alpine sleep 600 >/dev/null

if [ "$MODE" = watch ]; then
    step "attaching $CLI with 'nettap attach' ($SRV is picked up by its label)"
    docker exec "$NETTAP" nettap --data-dir /data attach "$CLI" >/dev/null
    for target in "$SRV" "$CLI"; do
        wait_for_log "$NETTAP" "tcpdump\[$target\]: .*listening on" "capture of $target"
        wait_for_log "$NETTAP" "tcpdump\[$target/lo\]: .*listening on" "DNS capture of $target"
    done
    # show which interface each container was resolved to
    docker logs "$NETTAP" 2>&1 | grep "attaching to" | sed 's/^/    /'
    # the server is picked up from Docker's start event, not the next poll
    docker run --rm --entrypoint python "$IMAGE" -c '
import sys, time
from datetime import datetime
from nettap.discovery import docker_time
started = docker_time(sys.argv[1])
line = next(l for l in sys.argv[2].splitlines() if "attaching to " + sys.argv[3] + " " in l)
attached = time.mktime(time.strptime(line[:19], "%Y-%m-%d %H:%M:%S")) + int(line[20:23]) / 1000
print(f"    {sys.argv[3]} attached {attached - started:.1f}s after it started")
' "$(docker inspect -f '{{.State.StartedAt}}' "$SRV")" "$(docker logs "$NETTAP" 2>&1)" "$SRV"
    CAPTURERS=("$NETTAP")
elif [ "$MODE" = sidecars ]; then
    for target in "$SRV" "$CLI"; do
        wait_until "sidecar for $target starting" sidecar_up "$target"
    done
    step "restarting $SRV: its sidecar must follow"
    docker restart "$SRV" >/dev/null
    wait_until "sidecar following the restarted $SRV" sidecar_up "$SRV"
    step "recreating $SRV under the same name: it must get a new sidecar"
    docker rm -f "$SRV" >/dev/null
    docker run -d --name "$SRV" --network "$NET" --label "$P=1" nginx:alpine >/dev/null
    wait_until "sidecar for the recreated $SRV" sidecar_up "$SRV"
    docker logs "$NETTAP" 2>&1 | grep -E "sidecar for|restart|recreated" | sed 's/^/    /'
    # stopping the supervisor stops (flushes) and removes the sidecars
    CAPTURERS=("$NETTAP")
else
    step "starting a sidecar on each"
    for target in "$SRV" "$CLI"; do
        docker run -d --name "$target-sidecar" --network "container:$target" \
            --cap-add NET_ADMIN --cap-add NET_RAW -v "$DATA:/data" \
            "$IMAGE" sidecar --target "$target" >/dev/null
    done
    for target in "$SRV" "$CLI"; do
        wait_for_log "$target-sidecar" "listening on" "sidecar for $target starting"
    done
    CAPTURERS=("$SRV-sidecar" "$CLI-sidecar")
fi

step "generating traffic"
T0=$(date +%s)
for _ in 1 2 3; do
    docker exec "$CLI" wget -q -O /dev/null "http://$SRV/"
done
if [ "$INTERNET" = 1 ]; then
    docker exec "$CLI" wget -q -O /dev/null https://example.com/
fi

# The running captures must store the traffic on their own, within about 15s
# (the files tcpdump still has open are parsed every 5s, see ingest.py).
step "waiting for the HTTP traffic to reach the flow store (no 'nettap enrich')"
http_stored() {
    docker run --rm -v "$DATA:/data" -e SRV="$SRV" -e CLI="$CLI" --entrypoint python "$IMAGE" -c '
import os, sqlite3, sys
c = sqlite3.connect("/data/nettap.db")
q = "SELECT COUNT(*) FROM flows WHERE container_name = ? AND {} = 80"
ok = all(c.execute(q.format(col), (os.environ[name],)).fetchone()[0]
         for name, col in (("CLI", "dst_port"), ("SRV", "src_port")))
sys.exit(0 if ok else 1)' 2>/dev/null
}
until http_stored; do
    if [ $(( $(date +%s) - T0 )) -ge 20 ]; then
        echo "  FAIL  HTTP traffic not in the flow store $(( $(date +%s) - T0 ))s after it was sent"
        exit 1
    fi
    sleep 1
done
LATENCY=$(( $(date +%s) - T0 ))
if [ "$LATENCY" -gt 15 ]; then
    echo "  FAIL  HTTP traffic took ${LATENCY}s to reach the flow store (limit 15s)"
    exit 1
fi
echo "  ok    HTTP traffic in the flow store ${LATENCY}s after it was sent, for both containers"

step "stopping capture (flushes the pcaps) and enriching"
docker stop -t 30 "${CAPTURERS[@]}" >/dev/null
if [ "$MODE" = sidecars ]; then
    left=$(docker ps -aq --filter "label=nettap.sidecar.selector=$P=1")
    [ -z "$left" ] || { echo "sidecars left after the supervisor stopped: $left"; exit 1; }
fi
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

# On this user-defined network lookups go to Docker's embedded DNS at
# 127.0.0.11 over lo; the sidecar's second capture there must have them.
answers = {ip for (a,) in conn.execute(
    "SELECT dns_answers FROM flows WHERE container_name = ? AND dns_query = ? "
    "AND dns_answers IS NOT NULL", (cli, srv)) for ip in json.loads(a)}
check(bool(answers & srv_ips), f"client's DNS lookup of the server captured on lo ({answers})")
check(analyze.hostnames(conn, cli).get(next(iter(answers & srv_ips), ""), {}).get("source")
      in ("http-host", "dns"), "server's IP named by the client's traffic")

if internet:
    internet_rows = analyze.external_destinations(conn, scope="internet")
    check(any(cli in (r["containers"] or "").split(",") for r in internet_rows),
          "client has internet destinations")
    check(all(r["dst_ip"] not in srv_ips | cli_ips for r in internet_rows),
          "no container's own IP listed as an internet destination")
    check(count("SELECT COUNT(*) FROM flows WHERE container_name = ? AND tls_sni = 'example.com'",
                cli) > 0, "TLS SNI example.com recorded")
    # catches captures landing on a shared interface (e.g. the host's eth0)
    check(count("SELECT COUNT(*) FROM flows WHERE container_name = ? AND tls_sni = 'example.com'",
                srv) == 0, "server capture has none of the client's internet traffic")
    check(any(r["hostname"] == "example.com" for r in analyze.hostnames(conn, cli).values()),
          "an IP named example.com")
    check(count("SELECT COUNT(*) FROM flows WHERE container_name = ? AND dns_query = 'example.com' "
                "AND dns_answers IS NOT NULL", cli) > 0, "DNS answer for example.com recorded")

data = report.build_report(conn, cli)
check(set(data["self_ips"]) == cli_ips, f"report identifies the client by its own IPs ({data['self_ips']})")
check(data["sent_bytes"] > 0 and data["received_bytes"] > 0, "report shows bytes sent and received")
peers = data["container_peers"]
check([p["container"] for p in peers] == [srv] and peers[0]["sent_bytes"] > 0
      and peers[0]["received_bytes"] > 0,
      f"report lists the server once as a peer, with traffic both ways ({peers})")
check(srv in report.render_text(data), "text report names the server")

print()
if failures:
    print(f"{len(failures)} check(s) failed")
    sys.exit(1)
print("all checks passed")
EOF
grep -q "^all checks passed$" "$DATA/checks.txt" || { echo "checks did not all pass"; exit 1; }
