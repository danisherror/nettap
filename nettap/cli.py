"""nettap command-line interface.

Typical usage:

    # start the daemon once (e.g. via docker-compose, restart: unless-stopped)
    nettap watch --label monitor=true

    # from anywhere else, attach/detach containers on the fly - the running
    # daemon picks these up within one poll interval (default 5s)
    nettap attach web db
    nettap detach web

    nettap status
    nettap analyze top-talkers --container web
    nettap analyze matrix
    nettap analyze dns
    nettap analyze external
    nettap analyze protocols
    nettap enrich                      # re-parse any pcaps missing from the DB
"""
from __future__ import annotations

import json
import logging
import signal
import threading
import time

import click

from . import storage
from .analyze import container_matrix, dns_queries, external_destinations, protocol_breakdown, top_talkers
from .capture import CaptureManager, capture_name, finished_pcaps, pcap_files, reap_orphans
from .controller import Selector, run as run_controller
from .ingest import enrich_pcap
from . import events as docker_events
from . import hostports
from .report import build_report, render_html, render_text
from .utils import format_table, parse_label_selector, setup_logging

logger = logging.getLogger("nettap.cli")

# how often the sidecar refreshes its live_sessions row (`status` uses it)
SIDECAR_HEARTBEAT_SECONDS = 5.0
# how often `sidecar --docker-api` re-reads the other containers
SIDECAR_PEER_SYNC_SECONDS = 30.0


def _docker_client():
    import docker
    return docker.from_env()


@click.group()
@click.option("--data-dir", default="data", show_default=True, help="Where pcaps and the SQLite DB live.")
@click.option("--log-level", default="INFO", show_default=True)
@click.pass_context
def cli(ctx, data_dir, log_level):
    setup_logging(log_level)
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = data_dir
    ctx.obj["db_path"] = f"{data_dir}/nettap.db"


@cli.command()
@click.argument("containers", nargs=-1)
@click.option("--label", help="Label selector, e.g. monitor=true (also honored continuously by 'watch').")
@click.pass_context
def attach(ctx, containers, label):
    """Request capture for one or more containers. Takes effect within one
    poll cycle of a running 'nettap watch' daemon (or as soon as one starts)."""
    if not containers and not label:
        raise click.UsageError("specify container name(s)/id(s), and/or --label key=value")
    conn = storage.connect(ctx.obj["db_path"])
    for ref in containers:
        storage.add_desired_ref(conn, ref)
    for k, v in parse_label_selector(label).items():
        storage.add_desired_label(conn, k, v)
    click.echo(f"requested: {list(containers)} label={label or ''} "
               f"- will attach within one poll cycle of 'nettap watch'")


@cli.command()
@click.argument("containers", nargs=-1)
@click.option("--label")
@click.option("--all", "all_", is_flag=True, help="Clear every explicit ref and label rule.")
@click.pass_context
def detach(ctx, containers, label, all_):
    """Stop requesting capture for containers (or label rules). Takes effect
    within one poll cycle of the running daemon."""
    conn = storage.connect(ctx.obj["db_path"])
    if all_:
        storage.clear_desired_state(conn)
        click.echo("cleared all desired state")
        return
    for ref in containers:
        storage.remove_desired_ref(conn, ref)
    for k, v in parse_label_selector(label).items():
        storage.remove_desired_label(conn, k, v)
    click.echo(f"detach requested: {list(containers)} label={label or ''}")


# how often the enrich loop parses what tcpdump has written since its last pass
ENRICH_INTERVAL_SECONDS = 5.0


def _enrich_loop(mgr: CaptureManager, db_path: str, stop, interval: float = ENRICH_INTERVAL_SECONDS):
    """Every `interval` seconds, store the packets each capture has written
    since the last pass - including the file tcpdump still has open (see
    ingest.py), so traffic shows up within seconds instead of after a pcap
    rotation.

    Runs on its own background thread - so it needs its OWN sqlite3
    connection. sqlite3.Connection objects are only usable from the thread
    that created them (check_same_thread defaults to True); sharing the main
    thread's connection here used to make this loop die on its first real
    insert with a silent sqlite3.ProgrammingError - no crash surfaced
    anywhere, it just stopped enriching forever, and only a manually-run
    `nettap enrich` (its own fresh process/thread/connection) ever worked.
    The per-iteration try/except is a second, independent safety net so a
    future bug here degrades to "logged and retried" instead of "silently
    dead thread" again."""
    conn = storage.connect(db_path)
    done: set[str] = set()
    while not stop["flag"]:
        try:
            now = time.time()
            for session in mgr.status():
                for pattern in (session["pcap_pattern"], session.get("dns_pcap_pattern")):
                    if not pattern:
                        continue
                    finished = set(finished_pcaps(pattern, session["rotate_seconds"], now))
                    for path in pcap_files(pattern):
                        if path in done:
                            continue
                        final = path in finished
                        n = enrich_pcap(conn, path, session["container_id"], session["container"],
                                        final=final, now=now)
                        if n:
                            logger.info("enriched %s -> %d flow rows", path, n)
                        if final:
                            done.add(path)
        except Exception:
            logger.exception("enrich loop iteration failed, continuing")
        time.sleep(interval)


def _sample_ports(db_path: str, container: str, stop) -> None:
    """sidecar --attribute-by-port: record the target's ports every
    hostports.SAMPLE_SECONDS. Own thread, so its own connection (see
    _enrich_loop)."""
    conn = storage.connect(db_path)
    while not stop["flag"]:
        try:
            hostports.record(conn, container, hostports.owned_ports(), time.time())
        except Exception:
            logger.exception("sampling the target's ports failed, continuing")
        time.sleep(hostports.SAMPLE_SECONDS)


def _sample_host_network_ports(mgr: CaptureManager, db_path: str, stop) -> None:
    """watch: record the ports of every attached --network host container
    every hostports.SAMPLE_SECONDS, from one `ss --cgroup` call. Own
    thread, so its own connection (see _enrich_loop)."""
    conn = storage.connect(db_path)
    while not stop["flag"]:
        try:
            names = {s["container_id"]: s["container"] for s in mgr.status()
                     if s.get("capture_scope") == "ports"}
            if names:
                now = time.time()
                for cid, ports in hostports.ports_by_container(names).items():
                    hostports.record(conn, names[cid], ports, now)
        except Exception:
            logger.exception("sampling host-network containers' ports failed, continuing")
        time.sleep(hostports.SAMPLE_SECONDS)


def _retention_options(f):
    """--pcap-max-age-hours / --pcap-max-size-mb, shared by watch and sidecar."""
    f = click.option("--pcap-max-size-mb", type=click.FloatRange(min=0, min_open=True), default=None,
                     help="Delete the oldest pcaps once data/pcap holds more than this. Off by default.")(f)
    f = click.option("--pcap-max-age-hours", type=click.FloatRange(min=0, min_open=True), default=None,
                     help="Delete pcaps older than this. Off by default.")(f)
    return f


def _retention_kwargs(max_age_hours, max_size_mb) -> dict:
    return {
        "max_age_seconds": max_age_hours * 3600 if max_age_hours else None,
        "max_bytes": int(max_size_mb * 1024 * 1024) if max_size_mb else None,
    }


@cli.command(name="watch")
@click.option("--label", help="Base label selector honored for the life of this daemon.")
@click.option("--all", "all_", is_flag=True, help="Attach to every running/new container.")
@click.option("--rotate-seconds", default=60, show_default=True)
@click.option("--poll-interval", default=5.0, show_default=True, help="Controller reconciliation interval, seconds.")
@click.option("--auto-enrich/--no-auto-enrich", default=True, help="Parse each rotated pcap into the DB automatically.")
@_retention_options
@click.pass_context
def watch_cmd(ctx, label, all_, rotate_seconds, poll_interval, auto_enrich,
              pcap_max_age_hours, pcap_max_size_mb):
    """Run the capture daemon in the foreground. This is the long-running
    process meant to run under docker-compose/systemd; 'attach'/'detach' from
    other invocations steer it via the shared database."""
    client = _docker_client()
    mgr = CaptureManager(ctx.obj["data_dir"], rotate_seconds=rotate_seconds,
                         **_retention_kwargs(pcap_max_age_hours, pcap_max_size_mb))
    conn = storage.connect(ctx.obj["db_path"])
    # rows still here mean an earlier daemon died without cleaning up
    reap_orphans(storage.list_live_sessions(conn))
    selector = Selector(match_all=all_, base_labels=parse_label_selector(label))

    stop = {"flag": False}

    def _stop(*_a):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if auto_enrich:
        threading.Thread(
            target=_enrich_loop, args=(mgr, ctx.obj["db_path"], stop), daemon=True
        ).start()
    threading.Thread(
        target=_sample_host_network_ports, args=(mgr, ctx.obj["db_path"], stop), daemon=True
    ).start()

    events_stop = threading.Event()
    wake = docker_events.start(client, events_stop)

    click.echo("nettap watching (Ctrl+C to stop)...")
    try:
        run_controller(client, conn, mgr, selector, poll_interval=poll_interval,
                       stop_flag=lambda: stop["flag"], wake=wake)
    finally:
        events_stop.set()
        for s in mgr.status():
            storage.clear_live_session(conn, s["container_id"])
        mgr.detach_all()


@cli.command()
@click.pass_context
def status(ctx):
    """Show the currently attached containers, as last reported by a running 'nettap watch' daemon."""
    conn = storage.connect(ctx.obj["db_path"])
    rows = storage.list_live_sessions(conn)
    if not rows:
        click.echo("no active sessions (is 'nettap watch' running?)")
        return
    now = time.time()
    for r in rows:
        line = f"{r['container_name']:<20} veth={r['veth']!s:<15} pcap={r['pcap_pattern']}"
        if storage.is_stale(r, now):
            line += (f"  STALE: no heartbeat for {_fmt_age(now - r['updated_at'])} - the "
                     "daemon that owns this probably died; its tcpdump may still be "
                     "running (a new 'nettap watch'/'sidecar' cleans it up on start)")
        click.echo(line)


def _fmt_age(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds}s"
    if seconds < 7200:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def _warn_if_unknown_container(conn, container: str | None) -> None:
    if not container:
        return
    known = storage.known_container_names(conn)
    if known and container not in known:
        click.echo(
            f"warning: no data for a container named '{container}' - "
            f"containers with captured data so far: {', '.join(known)}",
            err=True,
        )


@cli.group()
def analyze():
    """Query the flow store. Prints JSON (for scripts) unless given --format table."""


def _format_option(f):
    return click.option("--format", "fmt", type=click.Choice(["json", "table"]), default="json",
                        show_default=True,
                        help="'table' is easier to read in a terminal; 'json' has full values.")(f)


def _emit(rows: list[dict], fmt: str) -> None:
    click.echo(format_table(rows) if fmt == "table" else json.dumps(rows, indent=2))


@analyze.command("top-talkers")
@_format_option
@click.option("--container")
@click.option("--limit", default=10, show_default=True)
@click.pass_context
def analyze_top_talkers(ctx, container, limit, fmt):
    conn = storage.connect(ctx.obj["db_path"])
    _warn_if_unknown_container(conn, container)
    _emit(top_talkers(conn, container, limit), fmt)


@analyze.command("matrix")
@_format_option
@click.pass_context
def analyze_matrix(ctx, fmt):
    conn = storage.connect(ctx.obj["db_path"])
    _emit(container_matrix(conn), fmt)


@analyze.command("dns")
@_format_option
@click.option("--container")
@click.pass_context
def analyze_dns(ctx, container, fmt):
    conn = storage.connect(ctx.obj["db_path"])
    _warn_if_unknown_container(conn, container)
    _emit(dns_queries(conn, container), fmt)


@analyze.command("external")
@_format_option
@click.option("--scope", type=click.Choice(["all", "internet", "local"]), default="all",
              show_default=True,
              help="'internet' = publicly routable addresses only; 'local' = private, "
                   "link-local, multicast etc. (e.g. Docker Desktop's DNS resolver).")
@click.option("--container", help="Only count this container's capture.")
@click.pass_context
def analyze_external(ctx, scope, container, fmt):
    """Destinations that aren't a known container, each labelled with a scope."""
    conn = storage.connect(ctx.obj["db_path"])
    _warn_if_unknown_container(conn, container)
    rows = external_destinations(conn, scope=None if scope == "all" else scope,
                                 container=container)
    _emit(rows, fmt)


@analyze.command("protocols")
@_format_option
@click.option("--container")
@click.pass_context
def analyze_protocols(ctx, container, fmt):
    conn = storage.connect(ctx.obj["db_path"])
    _warn_if_unknown_container(conn, container)
    _emit(protocol_breakdown(conn, container), fmt)


@cli.command()
@click.option("--target", "target_label", required=True,
              help="Name to tag captured flows with - normally the target container's name/ID.")
@click.option("--iface", default="eth0", show_default=True,
              help="Interface to capture, inside THIS container's own network namespace.")
@click.option("--rotate-seconds", default=60, show_default=True)
@click.option("--auto-enrich/--no-auto-enrich", default=True)
@click.option("--docker-api", is_flag=True,
              help="Also record the other containers' names and IPs, and the target's "
                   "published ports, from the Docker API (needs /var/run/docker.sock "
                   "mounted), so the report can name peers that don't have a sidecar "
                   "of their own.")
@click.option("--attribute-by-port", is_flag=True,
              help="For a --network host target: capture on the host and keep only "
                   "traffic on ports the target's processes hold. Needs --pid "
                   "container:<target> and --cap-add SYS_PTRACE.")
@click.option("--allow-host-network", is_flag=True,
              help="Capture even if the target uses --network host. Everything the "
                   "Docker host sends or receives - other containers included - is then "
                   "labelled as the target.")
@_retention_options
@click.pass_context
def sidecar(ctx, target_label, iface, rotate_seconds, auto_enrich, docker_api,
            attribute_by_port, allow_host_network, pcap_max_age_hours, pcap_max_size_mb):
    """Capture mode for platforms where the veth/host-networking trick behind
    'watch' doesn't work - notably Docker Desktop for Mac/Windows, where
    `network_mode: host` is unreliable (see TODO.md). Start THIS container
    with `--network container:<target>` so it shares the target container's
    network namespace directly; this command then just tcpdumps that shared
    interface (default eth0), plus lookups to Docker's embedded DNS server on
    the shared lo - no nsenter, no host networking, and no
    /var/run/docker.sock or /var/run/docker/netns mounts needed (docker.sock
    only for --docker-api). One sidecar watches one target container; run
    one per container of interest."""
    from .discovery import (ContainerNetInfo, bridge_interfaces, interface_exists,
                            interface_ips, split_by_netns)

    if not interface_exists(iface):
        raise click.ClickException(
            f"no interface {iface!r} here - start this container with "
            f"--network container:<target> and make sure the target is running")

    # A --network host target shares the host's netns, and so does this
    # sidecar: tcpdump would see every container's traffic (NATed through
    # the host) plus the host's own, all labelled as the target - seen live
    # 2026-11-08 on Docker Desktop for Mac.
    bridges = bridge_interfaces()
    if bridges and not (allow_host_network or attribute_by_port):
        raise click.ClickException(
            f"the target seems to use --network host: this network namespace has "
            f"Docker's bridge interfaces ({', '.join(bridges)}), so it's the Docker "
            f"host's. A capture here would label every container's traffic, and the "
            f"host's own, as {target_label!r}. Pass --attribute-by-port (with --pid "
            f"container:<target> --cap-add SYS_PTRACE) to keep only the target's own "
            f"ports, or --allow-host-network to capture everything anyway (e.g. for a "
            f"Docker-in-Docker target, which has its own bridges)")
    if attribute_by_port:
        pids, denied = hostports.target_processes()
        if not pids:
            raise click.ClickException(
                "--attribute-by-port: no processes of the target are visible - start "
                "this container with --pid container:<target>")
        if denied:
            raise click.ClickException(
                f"--attribute-by-port: can't read the sockets of {len(denied)} of the "
                f"target's {len(pids)} processes (they run as another user) - start "
                f"this container with --cap-add SYS_PTRACE")
    elif bridges:
        logger.warning("--allow-host-network: capturing in a namespace with bridges %s - "
                       "all traffic here is labelled as %r", ", ".join(bridges), target_label)

    # We share the target's netns, so iface's addresses are the target's own.
    # Without them every reply packet into the target (dst = its own IP) gets
    # counted as "internet" traffic by analyze.external_destinations().
    info = ContainerNetInfo(
        container_id=target_label, name=target_label, image="",
        veth=iface, ip_addresses=interface_ips(iface), networks=[], labels={},
        sandbox_key=None, uses_host_network=False,
        capture_scope="ports" if attribute_by_port else None,
    )
    client = None
    if docker_api:
        try:
            client = _docker_client()
            client.ping()
        except Exception as e:
            raise click.ClickException(
                f"--docker-api: can't reach the Docker API ({e}) - mount it with "
                "-v /var/run/docker.sock:/var/run/docker.sock")

    def _sync_peers():
        try:
            target, peers = split_by_netns(client, info.ip_addresses.values())
            for peer in peers:
                storage.upsert_container(conn, peer)
            # Only the API knows the target's published ports and start time;
            # without them a peer reaching the target through a published
            # port isn't matched to it, and the target's own name can lose
            # to the real name another sidecar records for the same address
            # (see analyze._published_port_flows and _holders). Name and IPs
            # stay ours.
            if target and (target.published_ports, target.started_at) != \
                    (info.published_ports, info.started_at):
                info.published_ports = target.published_ports
                info.started_at = target.started_at
                storage.upsert_container(conn, info)
        except Exception:
            logger.exception("reading other containers from the Docker API failed, continuing")

    mgr = CaptureManager(ctx.obj["data_dir"], rotate_seconds=rotate_seconds, own_netns=True,
                         **_retention_kwargs(pcap_max_age_hours, pcap_max_size_mb))
    conn = storage.connect(ctx.obj["db_path"])
    storage.upsert_container(conn, info)
    # only our own row: other sidecars may share this DB from other containers
    reap_orphans([r for r in storage.list_live_sessions(conn)
                  if r["container_id"] == info.container_id])
    session = mgr.attach(info)
    if session:
        storage.save_capture_session(conn, session)

    stop = {"flag": False}

    def _stop(*_a):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if auto_enrich:
        threading.Thread(
            target=_enrich_loop, args=(mgr, ctx.obj["db_path"], stop), daemon=True
        ).start()
    if attribute_by_port:
        threading.Thread(
            target=_sample_ports, args=(ctx.obj["db_path"], info.name, stop), daemon=True
        ).start()

    click.echo(f"nettap sidecar capturing '{target_label}' on {iface} and lo (Ctrl+C to stop)...")
    last_beat = last_sync = 0.0
    try:
        while not stop["flag"]:
            if client and time.time() - last_sync >= SIDECAR_PEER_SYNC_SECONDS:
                _sync_peers()
                last_sync = time.time()
            if time.time() - last_beat >= SIDECAR_HEARTBEAT_SECONDS:
                storage.heartbeat_live_sessions(conn, [info.container_id], SIDECAR_HEARTBEAT_SECONDS)
                last_beat = time.time()
            if not interface_exists(iface):
                # Docker removes the shared interface when the target stops or
                # is removed, and a restarted target gets a fresh netns that
                # this process can't follow - tcpdump then just fails forever
                # (seen live 2026-11-08). Exit so it shows in `docker ps`.
                # `docker start` on this container rejoins a restarted target;
                # a removed target needs a new sidecar.
                logger.error(
                    "%s disappeared: the target container stopped or was removed. "
                    "Exiting - once the target is running again, `docker start` this "
                    "container (or recreate it if the target was recreated)", iface)
                raise SystemExit(3)
            for restarted in mgr.restart_dead():
                storage.save_capture_session(conn, restarted)
            try:
                mgr.enforce_retention()
            except Exception:
                logger.exception("pcap retention failed, continuing")
            time.sleep(1)
    finally:
        storage.clear_live_session(conn, info.container_id)
        mgr.detach_all()


@cli.command(name="sidecars")
@click.option("--label", required=True,
              help="Label selector for the containers to capture, e.g. monitor=true.")
@click.option("--poll-interval", default=5.0, show_default=True,
              help="How often to check the containers and their sidecars, seconds.")
@click.option("--image", default=None,
              help="Image for the sidecars. Default: this container's own image "
                   "(or 'nettap' when not run in a container).")
@click.option("--data-volume", default=None,
              help="Host path or volume name to mount at /data in each sidecar. "
                   "Default: whatever is mounted at --data-dir in this container "
                   "(or its absolute path when not run in a container).")
@click.option("--rotate-seconds", default=60, show_default=True)
@click.option("--docker-api", is_flag=True,
              help="Give each sidecar docker.sock and pass it --docker-api.")
@click.option("--keep-sidecars", is_flag=True,
              help="Leave the sidecars running when this command exits.")
@_retention_options
@click.pass_context
def sidecars_cmd(ctx, label, poll_interval, image, data_volume, rotate_seconds, docker_api,
                 keep_sidecars, pcap_max_age_hours, pcap_max_size_mb):
    """Run one sidecar per container matching --label, and keep them
    running: a sidecar is started again when its target comes back after a
    stop or restart, and recreated when the target is recreated under the
    same name. Needs /var/run/docker.sock. Sidecars are named
    nettap-sidecar-<target> and removed when this exits (unless
    --keep-sidecars)."""
    from .supervisor import SidecarSpec, Supervisor, default_spec, own_container

    labels = parse_label_selector(label)
    try:
        client = _docker_client()
        client.ping()
    except Exception as e:
        raise click.ClickException(
            f"can't reach the Docker API ({e}) - mount it with "
            "-v /var/run/docker.sock:/var/run/docker.sock")
    if image is None or data_volume is None:
        try:
            default_image, default_data = default_spec(client, ctx.obj["data_dir"])
        except RuntimeError as e:
            raise click.ClickException(str(e))
        image, data_volume = image or default_image, data_volume or default_data

    args = ["--rotate-seconds", str(rotate_seconds)]
    if pcap_max_age_hours:
        args += ["--pcap-max-age-hours", str(pcap_max_age_hours)]
    if pcap_max_size_mb:
        args += ["--pcap-max-size-mb", str(pcap_max_size_mb)]
    me = own_container(client)
    sup = Supervisor(client, labels,
                     SidecarSpec(image=image, data_source=data_volume, sidecar_args=args,
                                 docker_api=docker_api),
                     exclude_ids={me.id} if me else set())

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_a: stop.set())
    signal.signal(signal.SIGINT, lambda *_a: stop.set())
    wake = docker_events.start(client, stop)

    click.echo(f"nettap supervising sidecars for containers with {label} "
               f"(image {image}, data {data_volume}; Ctrl+C to stop)...")
    try:
        while not stop.is_set():
            try:
                sup.reconcile()
            except Exception:
                logger.exception("sidecar supervision pass failed, continuing")
            wake.wait(poll_interval)
            wake.clear()
    finally:
        if not keep_sidecars:
            click.echo("removing sidecars...")
            sup.remove_all()


@cli.command()
@click.option("--container", required=True, help="Container name to summarize.")
@click.option("--format", "fmt", type=click.Choice(["text", "html"]), default="text", show_default=True)
@click.option("--out", default=None,
              help="Output file path. Defaults to <data-dir>/<container>_report.html for "
                   "--format html (so it lands in the bind-mounted data dir, on the host "
                   "filesystem, ready to double-click open); prints to the terminal for "
                   "--format text unless --out is given.")
@click.pass_context
def report(ctx, container, fmt, out):
    """Plain-language traffic summary for one container - readable without
    knowing what a pcap or a 5-tuple is. Meant for `docker exec ... nettap
    report --container X` (text, straight to your terminal) or `--format
    html` (a single file you can open in a browser)."""
    conn = storage.connect(ctx.obj["db_path"])
    known = storage.known_container_names(conn)
    if known and container not in known:
        click.echo(
            f"No data for a container named '{container}'.\n"
            f"Containers with captured data so far: {', '.join(known)}\n"
            f"(--container must match the --target name the capture was started with, "
            f"not necessarily the container's current name in 'docker ps')",
            err=True,
        )
        raise SystemExit(1)
    data = build_report(conn, container)
    if fmt == "html":
        content = render_html(data)
        out = out or f"{ctx.obj['data_dir']}/{container}_report.html"
        with open(out, "w") as f:
            f.write(content)
        click.echo(f"wrote {out} - open it in a browser (it's on your host machine too, "
                   f"under the bind-mounted data directory)")
    else:
        content = render_text(data)
        if out:
            with open(out, "w") as f:
                f.write(content)
            click.echo(f"wrote {out}")
        else:
            click.echo(content)


@cli.command()
@click.option("--pcap-dir", default=None, help="Defaults to <data-dir>/pcap")
@click.pass_context
def enrich(ctx, pcap_dir):
    """Batch-parse any pcap files not yet reflected in the DB (re-run after a
    crash, or against old captures)."""
    import glob
    conn = storage.connect(ctx.obj["db_path"])
    pcap_dir = pcap_dir or f"{ctx.obj['data_dir']}/pcap"
    # Files a running daemon is still writing are left to its enrich loop;
    # everything else is parsed from wherever the last pass stopped.
    now = time.time()
    writing = set()
    for row in storage.list_live_sessions(conn):
        if storage.is_stale(row, now):
            continue
        for pattern in (row["pcap_pattern"], row.get("dns_pcap_pattern")):
            if pattern:
                writing |= set(pcap_files(pattern)) - set(
                    finished_pcaps(pattern, row.get("rotate_seconds") or 60, now))
    total = 0
    for path in sorted(glob.glob(f"{pcap_dir}/*.pcap")):
        if path in writing:
            continue
        name = capture_name(path) or path.split("/")[-1].rsplit("_", 1)[0]
        total += enrich_pcap(conn, path, "", name, final=True)
    click.echo(f"inserted {total} flow rows")


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
