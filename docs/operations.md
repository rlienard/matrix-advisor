# Operations

Running Matrix Advisor in production on one host (the *small* deployment: up to about 5,000 flows/s).
Everything below is set with environment variables or compose files, not from the UI.

## HTTPS

`deploy/tls/docker-compose.tls.yml` adds Caddy in front of the application and stops publishing the
application port, so only 443 (and 80, for the redirect and ACME) is reachable:

```bash
MA_DOMAIN=matrix-advisor.example.net docker compose -f docker-compose.yml -f deploy/tls/docker-compose.tls.yml up -d
```

| `MA_TLS` | Certificate |
| --- | --- |
| `internal` (default) | Issued by Caddy's own CA; trust it once in the browser (`docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt`). |
| an e-mail address | Public ACME certificate; needs a public DNS name and ports 80/443 reachable. |
| `/certs/server.crt /certs/server.key` | Your own certificate (enterprise PKI), placed in `./certs`. |

Caddy adds HSTS and the usual security headers and refuses `/metrics` from outside. The application
trusts the proxy's `X-Forwarded-Proto` (`MA_FORWARDED_ALLOW_IPS`), so the session cookie is marked
`Secure`. Requires Docker Compose 2.24 or later.

## Metrics and alerts

Set `MA_METRICS_TOKEN` to enable `GET /metrics` (Prometheus text format, `Authorization: Bearer <token>`).
Without the variable the endpoint does not exist. Metrics hold counts, durations and states only: no
address, SGT pair or secret.

| Metric | Meaning |
| --- | --- |
| `ma_last_record_age_seconds` | Age of the newest flow: switches, GoFlow2 or ingest stopped when it grows |
| `ma_ingest_lag_bytes` | GoFlow2 output not read yet: ingest falls behind when it keeps growing |
| `ma_ingest_records_total`, `ma_ingest_malformed_total`, `ma_ingest_dropped_exporter_total` | Ingest counters |
| `ma_ingest_sgt_from_flow_total`, `ma_ingest_unknown_tag_total` | SGT taken from the flow record, unknown tag values |
| `ma_flows_per_second`, `ma_ingest_tick_seconds` | Throughput and duration of the last 5 s tick |
| `ma_advisor_run_seconds`, `ma_advisor_last_run_age_seconds`, `ma_proposals{status}` | Advisor |
| `ma_ise_online`, `ma_ise_last_sync_age_seconds`, `ma_ise_reconcile_seconds`, `ma_ise_{sgts,sgacls,cells}` | ISE matrix cache |
| `ma_pxgrid_configured`, `ma_pxgrid_online`, `ma_pxgrid_websocket`, `ma_resolver_entries{source}` | pxGrid context |
| `ma_llm_online`, `ma_llm_latency_seconds` | Model |
| `ma_store_rows{table}`, `ma_store_file_bytes` | Database size |
| `ma_backup_last_success_timestamp_seconds`, `ma_backup_failures_total` | Backups |

`deploy/prometheus/prometheus.yml` scrapes the application, GoFlow2's own metrics (port 8080 in its
container) and node_exporter on the collector host; `deploy/prometheus/alerts.yml` has the alerts:
no flows, ingest backlog, kernel UDP drops (`node_netstat_Udp_RcvbufErrors`), ISE or pxGrid down,
advisor stalled, backup missing.

### Collector host

UDP packets dropped by the kernel are invisible to GoFlow2 and to the application. On the collector
host, raise the socket buffers and watch `RcvbufErrors`:

```bash
sysctl -w net.core.rmem_max=33554432 net.core.rmem_default=33554432
grep Udp: /proc/net/snmp      # RcvbufErrors must stay flat
```

Point each switch at one collector only (NetFlow v9 and IPFIX templates are per exporter), restrict
UDP 2055/4739 to the switch management addresses, and do not sample access switches: default-deny
readiness depends on seeing rare flows.

## Backups

A backup folder is written every `MA_BACKUP_HOURS` (default 24, `0` disables), the first one 10
minutes after start. It holds a consistent copy of the database taken while the app runs, plus
`config.yaml` and `secrets.json`, in `MA_BACKUP_DIR` (default `/data/backups`), readable by the
owner only (folder 0700, files 0600). The newest `MA_BACKUP_KEEP` (default 7) are kept. Ingest and
the API pause while the database is copied. Each backup is audited.

The volume holds secrets: copy `/data/backups` off the host with the same care as `secrets.json`.
The Parquet archive (`/data/parquet`) is not in the backup folders; back it up separately if the raw
flows must be kept.

Restore:

```bash
docker compose stop matrix-advisor
docker compose run --rm --entrypoint sh matrix-advisor -c '
  b=/data/backups/backup-YYYYMMDD-HHMMSS-ffffff &&
  cp "$b/matrix-advisor.duckdb" /data/matrix-advisor.duckdb && rm -f /data/matrix-advisor.duckdb.wal &&
  cp "$b/config.yaml" "$b/secrets.json" /data/'
docker compose start matrix-advisor
```
