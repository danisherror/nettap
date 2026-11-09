#!/usr/bin/env bash
# Measure how many connections `sidecar --attribute-by-port` catches for a
# --network host target (hostports.py samples the target's sockets every
# 0.25s, so a connection that opens and closes between two samples is lost).
#
# Workloads, each N connections (default 100):
#   outgoing  the target runs `wget` N times against an nginx container -
#             one short-lived process and connection each
#   held      the target opens N/5 connections to nginx with `nc` and keeps
#             each open for 0.5s - longer than one sample
#   incoming  a server in the target (busybox httpd on a fixed port) answers
#             N requests from another container - a listening port, held
#             the whole time
# A connection counts as caught when any of its packets (matched by the
# client's source port) made it into the target's flows.
#
# Usage: scripts/hostports_accuracy.sh [-n N] [--min-incoming PCT] [--keep]
# Fails if fewer than --min-incoming percent (default 95) of the incoming
# connections are caught; the outgoing rate is only reported.
# Everything it creates is named nettap-acc-<random> and removed on exit.
set -euo pipefail

N=100
MIN_INCOMING=95
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        -n) N="$2"; shift ;;
        --min-incoming) MIN_INCOMING="$2"; shift ;;
        --keep) KEEP=1 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

cd "$(dirname "$0")/.."
P="nettap-acc-$(printf "%04x%04x" $RANDOM $RANDOM)"
DATA="$(mktemp -d "${TMPDIR:-/tmp}/$P.XXXXXX")"
IMAGE="$P-image"
NET="$P-net"
SRV="$P-srv"          # nginx, on a bridge network
TGT="$P-target"       # --network host, the container being measured
CLI="$P-client"       # calls the target's httpd
CAP="$P-sidecar"
PORT=$(( 20000 + RANDOM % 10000 ))

cleanup() {
    docker rm -f "$CAP" "$TGT" "$SRV" "$CLI" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    if [ "$KEEP" = 1 ]; then
        echo "data kept in $DATA"
    else
        docker run --rm -v "$DATA:/data" --entrypoint sh "$IMAGE" \
            -c 'rm -rf /data/* /data/.[!.]*' >/dev/null 2>&1 || true
        rm -rf "$DATA" || echo "could not remove $DATA" >&2
    fi
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step() { echo "==> $*"; }

step "building nettap image"
docker build -q -t "$IMAGE" . >/dev/null
docker network create "$NET" >/dev/null

step "starting nginx ($SRV), the host-network target and its sidecar"
docker run -d --name "$SRV" --network "$NET" nginx:alpine >/dev/null
SRV_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$SRV")
GATEWAY=$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "$NET")
# The sidecar captures the test network's bridge instead of eth0: traffic
# between the host's network and a container never crosses eth0, and what's
# measured here is the socket sampling, which is the same on any interface.
# Docker names a user-defined network's bridge br-<first 12 of its ID>.
BRIDGE="br-$(docker network inspect -f '{{.Id}}' "$NET" | cut -c1-12)"
docker run -d --name "$TGT" --network host busybox httpd -f -p "$PORT" -h /etc >/dev/null
docker run -d --name "$CAP" --network "container:$TGT" --pid "container:$TGT" \
    --cap-add NET_RAW --cap-add SYS_PTRACE -v "$DATA:/data" \
    "$IMAGE" sidecar --target "$TGT" --attribute-by-port --iface "$BRIDGE" >/dev/null
for _ in $(seq 30); do
    docker logs "$CAP" 2>&1 | grep -q "listening on" && break
    sleep 1
done
docker logs "$CAP" 2>&1 | grep -q "listening on" || { docker logs "$CAP"; exit 1; }
sleep 2  # a few socket samples, so the httpd's listening port is recorded

step "outgoing: $N wget runs from the target to $SRV ($SRV_IP)"
docker exec "$TGT" sh -c "i=0; while [ \$i -lt $N ]; do wget -q -O /dev/null http://$SRV_IP/; i=\$((i+1)); done"

HELD=$(( N / 5 ))
sleep 1
docker run --rm -v "$DATA:/data" --entrypoint python "$IMAGE" -c \
    'import time; open("/data/held_start", "w").write(str(time.time()))'
step "held: $HELD connections from the target to $SRV, each kept open 0.5s"
docker exec "$TGT" sh -c "i=0; while [ \$i -lt $HELD ]; do { printf 'GET / HTTP/1.0\r\n\r\n'; sleep 0.5; } | nc $SRV_IP 80 >/dev/null; i=\$((i+1)); done"

step "incoming: $N requests from $CLI to the target's httpd ($GATEWAY:$PORT)"
docker run -d --name "$CLI" --network "$NET" busybox sleep 600 >/dev/null
docker exec "$CLI" sh -c "i=0; while [ \$i -lt $N ]; do wget -q -O /dev/null http://$GATEWAY:$PORT/hostname || true; i=\$((i+1)); done"
sleep 3  # past the enrich holdback, so the last packets are matched to their ports

step "stopping capture and enriching"
docker stop -t 30 "$CAP" >/dev/null
docker run --rm -v "$DATA:/data" "$IMAGE" enrich >/dev/null

step "results"
docker run -i --rm -v "$DATA:/data" -e TGT="$TGT" -e SRV_IP="$SRV_IP" -e PORT="$PORT" -e N="$N" -e HELD="$HELD" \
    -e MIN_INCOMING="$MIN_INCOMING" --entrypoint python "$IMAGE" - <<'EOF' | tee "$DATA/results.txt"
import os, sqlite3, sys
c = sqlite3.connect("/data/nettap.db")
tgt, srv_ip, port, n = os.environ["TGT"], os.environ["SRV_IP"], int(os.environ["PORT"]), int(os.environ["N"])
# wget runs come first, then the held nc connections; split them by time
# at the first packet after the gap the script logs between the two
q = ("SELECT src_port, MIN(ts) AS t FROM flows WHERE container_name = ? AND transport = 'tcp' "
     "AND dst_ip = ? AND dst_port = 80 AND ts {} ? GROUP BY src_port")
split = float(open("/data/held_start").read())
out = len(c.execute(q.format("<"), (tgt, srv_ip, split)).fetchall())
held_caught = len(c.execute(q.format(">="), (tgt, srv_ip, split)).fetchall())
# the held connections are the ones after the wget runs: nc's ports
held = int(os.environ["HELD"])
inc = c.execute("SELECT COUNT(DISTINCT src_port) FROM flows WHERE container_name = ? AND transport = 'tcp' "
                "AND dst_port = ?", (tgt, port)).fetchone()[0]
print(f"  outgoing (short-lived wget connections): {out}/{n} caught = {100 * out / n:.0f}%")
print(f"  held 0.5s (outgoing, nc):                {held_caught}/{held} caught = {100 * held_caught / held:.0f}%")
print(f"  incoming (to a listening port):          {inc}/{n} caught = {100 * inc / n:.0f}%")
ok = 100 * inc / n >= float(os.environ["MIN_INCOMING"])
print("incoming rate ok" if ok else f"incoming rate below {os.environ['MIN_INCOMING']}%")
sys.exit(0 if ok else 1)
EOF
