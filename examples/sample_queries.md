# Sample session

```
$ docker compose up -d --build
$ docker run -d --name web --label monitor=true nginx
$ docker run -d --name db  --label monitor=true postgres

# nettap (running via compose with --label monitor=true) picks both up
# within one poll cycle (default 5s). Confirm:
$ docker compose exec nettap nettap --data-dir /data status
web                  veth=veth3a1f9c2 pcap=/data/pcap/web_%Y%m%d%H%M%S.pcap
db                   veth=veth7bb210e pcap=/data/pcap/db_%Y%m%d%H%M%S.pcap

# attach one more container ad hoc, without restarting the daemon
$ docker run -d --name cache redis
$ docker compose exec nettap nettap --data-dir /data attach cache

# after some traffic has flowed and a pcap rotation has happened (default 60s)
$ docker compose exec nettap nettap --data-dir /data analyze top-talkers --container web
[
  {
    "src_ip": "172.18.0.2",
    "dst_ip": "172.18.0.3",
    "bytes": 48213,
    "packets": 412
  }
]

$ docker compose exec nettap nettap --data-dir /data analyze matrix
[
  {"src_container": "web", "dst_container": "db", "bytes": 48213, "packets": 412}
]

$ docker compose exec nettap nettap --data-dir /data analyze external
[
  {"dst_ip": "1.1.1.1", "bytes": 1320, "packets": 9, "containers": "web"}
]

$ docker compose exec nettap nettap --data-dir /data analyze dns --container web
[
  {"container_name": "web", "dns_query": "registry.npmjs.org", "lookups": 3}
]

# stop watching a container (capture stops, existing pcaps/flow rows stay)
$ docker compose exec nettap nettap --data-dir /data detach cache
```

Raw pcaps stay in `./data/pcap/` on the host (bind-mounted), so `wireshark
./data/pcap/web_20260902120000.pcap` works directly for a deep dive whenever
the SQL-level view in `analyze` isn't enough.
