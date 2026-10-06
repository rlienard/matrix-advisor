# Architecture

## Data path

1. **Collection.** GoFlow2 listens for NetFlow v9 (UDP 2055) and IPFIX (UDP 4739) and appends one
   JSON object per flow to `/flows/goflow2.ndjson`.
2. **Ingest** (`matrix_advisor/ingest`). Every 5 s the pipeline reads the new complete lines
   (rotation and truncation aware; the file is truncated once fully read and above 256 MB).
   - *Exporter filter*: only exporters inside `collector.allowed_exporters` are kept.
   - *Orientation*: NetFlow sees both directions of a conversation. Each record is folded onto the
     request direction (client → service port) using a port score: well-known ports, known service
     ports, registered, ephemeral. A reply from a web server is therefore not mistaken for traffic
     from the server group to the client group.
   - *SGT attribution*: the group tag exported in the flow record (`src_sgt`/`dst_sgt`, Cisco CTS
     fields mapped by `deploy/goflow2/mapping.yaml`) when its value is in the ISE SGT table and
     `collector.sgt_source` is `auto`; otherwise IP resolution: pxGrid session (exact IP) >
     SXP/IP-SGT binding (prefix) > static binding from the configuration > `Unknown` (SGT 0, the
     tag the switches enforce for any unclassified address, Internet destinations included). Tags are swapped together with the addresses when a
     reply is folded onto its request. Ingestion waits (up to 3 minutes) for the ISE SGT table and
     the first pxGrid context so that early flows are not attributed to `Unknown` for good.
     `/api/status` counts flow sides attributed from tags (`sgt_from_flow`) and unknown tag values
     (`unknown_tag`).
3. **Storage** (`matrix_advisor/store.py`, DuckDB).
   - `pair_minutes`: per-minute aggregates per (SGT pair, protocol, port), no address, 7 days. Read by
     every advisor run and dashboard load (flows, first/last seen, activity, timing), so their cost
     does not grow with the number of hosts.
   - `host_daily`: source addresses seen per day and (SGT pair, protocol, port), 7 days. Host counts.
   - `host_minutes`: (source, destination) address pairs seen per minute and SGT pair, 7 days. Read for
     one pair at a time to detect periodic (beaconing) behaviour.
   - Each 5 s ingest batch appends rows; every 10 minutes the last 30 minutes are compacted (rows of the
     same key merged), then today and yesterday are rolled up.
   - `pair_daily`: daily rollup per (SGT pair, protocol, port), `retention_days`.
   - Databases of earlier versions (single `flow_minutes` table keyed by addresses) are migrated on start.
   - Raw records staged then written to Parquet every `rotate_minutes` (`parquet_dir/date=…`).
   - `proposals`, `coverage_history`, `audit`, `meta`.

## ISE integration (`matrix_advisor/ise`)

- **ERS** (`client.py`): paginated reads of SGTs, SGACLs and egress matrix cells (details fetched
  with bounded concurrency), creation and update of SGACLs and cells, `generationId` honoured on
  SGACL updates. `GET /api/v1/deployment/node` lists nodes; nodes whose services or roles mention
  pxGrid are offered in the configuration UI.
- **pxGrid 2.0** (`pxgrid.py`): `AccountActivate` (and `AccountCreate` for password auth),
  `ServiceLookup`, `AccessSecret`, then `getSessions` (com.cisco.ise.session) and `getBindings`
  (com.cisco.ise.sxp). A STOMP-over-websocket subscription follows `sessionTopic` and every
  `*Topic` of `com.cisco.ise.config.trustsec`; a TrustSec message triggers a reconciliation.
  When the websocket is not reachable, the service polls every `poll_seconds`.
- **Reconciliation** (`service.py`): the matrix cache is rebuilt from scratch every
  `reconcile_minutes`, on change notification, after each write and on demand from the UI.
  Requests are debounced: a burst (pxGrid notifications, bulk approvals) leads to one full read,
  5 s after the last request and at most 30 s after the first. After a write, the cell written and
  its SGACLs are re-read at once, so the cache is exact for that pair before the full read.
- **IP → SGT resolver** (`ingest/resolver.py`): prefixes are indexed by length (one dictionary probe per
  distinct length); a pxGrid session event evicts only the addresses it names from the lookup cache.

## Coverage

For a pair (src, dst) and an observed port, `Matrix.evaluate` applies the cell's SGACLs in order with
first-match semantics, then the cell default rule, then the matrix default. `MONITOR` cells count as
permitted (they log instead of dropping). A pair is:

- `allowed`: every observed port is permitted;
- `partial`: a contract exists on the cell but at least one observed port is not permitted;
- `pending`: nothing permits it, default-deny would drop it;
- `rejected`: the last proposal was rejected (it stays denied).

## Advisor (`matrix_advisor/agent`)

Runs every `aggregation_seconds` in `event` mode (only new pairs/ports cost an LLM call) or every
`scheduled_minutes`. Pairs are taken from the whole retained history (`max(7, retention_days)`
days, daily rollups beyond the 7 days of per-minute detail), so a monthly job seen weeks ago is still
proposed before default-deny. After the learning phase, for each non-covered pair without an open
proposal:

1. **Kind** (deterministic): `external` if a side is not in the ISE SGT table; `extend` if the cell
   has a contract (the prefixed one if any); `unknown` towards SGT 0: with `ise.egress_firewall`
   (default) the built-in `Permit IP` is assigned (or a `permit ip` SGACL created), since the egress
   firewall filters that traffic; without it, least privilege like `new`. A read-only contract such
   as `Permit IP` is always cloned when edited. `reuse` if an existing SGACL covers all observed ports with at most two
   extra permits (same destination group first, then fewest extras); else `new` with one permit per
   observed port and `deny ip log`.
2. **Features** (no IP): ports with flow and host counts, number of source hosts, first seen,
   off-hours ratio, periodic host pairs and their interval (beaconing), activity (distinct days with
   traffic out of the days of history, days since the last flow).
3. **Heuristics** (`risk.py`): risk floor and reasons. A *rare* pair (seen on at most 2 days out of
   at least 7 days of history) is raised to `medium` / `review`: it may be a periodic job whose ports
   were not all observed.
4. **LLM** (`llm.py`, `prompts.py`): JSON answer `{risk, recommendation, justification}`. The final
   risk is the max of heuristic and model risk. Payloads are checked for IP addresses before sending.

A rejected proposal is not re-proposed unless new ports appear. An open proposal edited by the admin
is never replaced automatically.

## Approval (`actions.py`)

1. Validate the (possibly edited) SGACL.
2. Lock writes, re-read the cell from ISE, compare its fingerprint with the one recorded at
   proposal time. Different → HTTP 409 with the current contracts; the UI offers *merge*.
3. Apply:
   - `new` (and `unknown` without a base contract): create `<prefix><src>_to_<dst>`, add it to the cell;
   - `reuse` (and `unknown` with `Permit IP`) unchanged: add the existing SGACL to the cell;
   - changed existing contract, `clone`: create `<prefix><base>_<src>` and point only this cell to it;
   - changed existing contract, `inplace`: allowed only if the impact analysis (over the same retained
     history as the advisor) finds no observed traffic
     of another pair using the contract that would become denied; the SGACL is re-read and must not
     have changed since the proposal.
4. Create or update the cell: new cells get `MONITOR` or `ENABLED` per `write_mode`, existing cells
   keep their status. Reconcile, store the result and audit the decision.

## Settings and certificates

- `ise.verify_tls` and `ise.ca_cert` apply to ERS/OpenAPI and pxGrid alike (older per-API keys are
  migrated on load). `ise.pxgrid.secondary_node` is tried when the primary node cannot be reached.
- pxGrid client certificate: generated (`POST /api/ise/pxgrid/certificate`: RSA 2048, self-signed,
  clientAuth, new file names each time) or uploaded (`POST /api/ise/certificates/upload`, PEM or DER,
  key checked with its password). Files live in `<data>/certs`, keys with mode 0600; the configuration
  points to them only once the operator saves. With `import_to_ise_trust`, generation also imports
  the public certificate into the ISE trusted store (`POST /api/v1/certs/trusted-certificate/import`,
  trusted for client authentication); the click is the explicit approval, and both the generation
  and the import are audited.
- `POST /api/llm/models` lists the models of an Ollama (`/api/tags`, `/api/ps`) or vLLM
  (`/v1/models`) server from unsaved settings. A *local* instance is `http://<host>:<port>` where the
  host is `localhost`, or inside a container the first of `host.docker.internal`,
  `host.lima.internal`, `host.containers.internal` that resolves, else the default gateway
  (`MA_LLM_LOCAL_HOST` overrides).
- `POST /api/config/test/{llm|ise|pxgrid|collector}` tests one service with unsaved settings; the
  LLM status also turns red as soon as a real call times out, and green on the next answer.
