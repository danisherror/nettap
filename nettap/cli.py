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
from .capture import CaptureManager, capture_name, pcap_files, reap_orphans
from .controller import Selector, run as run_controller
from .enrich import parse_pcap
from .report import build_report, render_html, render_text
from .utils import format_table, parse_label_selector, setup_logging

logger = logging.getLogger("nettap.cli")

# how often the sidecar refreshes its live_sessions row (`status` uses it)
SIDECAR_HEARTBEAT_SECONDS = 5.0


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


def _enrich_loop(mgr: CaptureManager, db_path: str, poll_interval, stop):
    """Runs on its own background thread - so it needs its OWN sqlite3
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
    seen: set[str] = set()
    while not stop["flag"]:
        try:
            for session in mgr.status():
                for pattern in (session["pcap_pattern"], session.get("dns_pcap_pattern")):
                    if not pattern:
                        continue
                    # the most recent file is still being written by tcpdump;
                    # only enrich files that have already been rotated past
                    for path in pcap_files(pattern)[:-1]:
                        if path in seen:
                            continue
                        seen.add(path)
                        rows = parse_pcap(path, session["container_id"], session["container"])
                        storage.insert_flows(conn, rows)
                        logger.info("enriched %s -> %d flow rows", path, len(rows))
        except Exception:
            logger.exception("enrich loop iteration failed, continuing")
        time.sleep(max(poll_interval, 5))


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
            target=_enrich_loop, args=(mgr, ctx.obj["db_path"], poll_interval, stop), daemon=True
        ).start()

    click.echo("nettap watching (Ctrl+C to stop)...")
    try:
        run_controller(client, conn, mgr, selector, poll_interval=poll_interval, stop_flag=lambda: stop["flag"])
    finally:
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
@click.pass_context
def analyze_external(ctx, scope, fmt):
    """Destinations that aren't a known container, each labelled with a scope."""
    conn = storage.connect(ctx.obj["db_path"])
    rows = external_destinations(conn, scope=None if scope == "all" else scope)
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
@_retention_options
@click.pass_context
def sidecar(ctx, target_label, iface, rotate_seconds, auto_enrich,
            pcap_max_age_hours, pcap_max_size_mb):
    """Capture mode for platforms where the veth/host-networking trick behind
    'watch' doesn't work - notably Docker Desktop for Mac/Windows, where
    `network_mode: host` is unreliable (see TODO.md). Start THIS container
    with `--network container:<target>` so it shares the target container's
    network namespace directly; this command then just tcpdumps that shared
    interface (default eth0), plus lookups to Docker's embedded DNS server on
    the shared lo - no nsenter, no host networking, and no
    /var/run/docker.sock or /var/run/docker/netns mounts needed. One sidecar
    watches one target container; run one per container of interest."""
    from .discovery import ContainerNetInfo, interface_exists, interface_ips

    if not interface_exists(iface):
        raise click.ClickException(
            f"no interface {iface!r} here - start this container with "
            f"--network container:<target> and make sure the target is running")

    # We share the target's netns, so iface's addresses are the target's own.
    # Without them every reply packet into the target (dst = its own IP) gets
    # counted as "internet" traffic by analyze.external_destinations().
    info = ContainerNetInfo(
        container_id=target_label, name=target_label, image="",
        veth=iface, ip_addresses=interface_ips(iface), networks=[], labels={},
        sandbox_key=None, uses_host_network=False,
    )
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
            target=_enrich_loop, args=(mgr, ctx.obj["db_path"], rotate_seconds, stop), daemon=True
        ).start()

    click.echo(f"nettap sidecar capturing '{target_label}' on {iface} and lo (Ctrl+C to stop)...")
    last_beat = 0.0
    try:
        while not stop["flag"]:
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
    already = {r["pcap_file"] for r in conn.execute("SELECT DISTINCT pcap_file FROM flows")}
    total = 0
    for path in sorted(glob.glob(f"{pcap_dir}/*.pcap")):
        if path in already:
            continue
        name = capture_name(path) or path.split("/")[-1].rsplit("_", 1)[0]
        rows = parse_pcap(path, container_id="", container_name=name)
        total += storage.insert_flows(conn, rows)
    click.echo(f"inserted {total} flow rows")


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
