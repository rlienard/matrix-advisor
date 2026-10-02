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
     SXP/IP-SGT binding (prefix) > static binding from the configuration > `Internet` (public
     address) or `Unknown` (private address). Tags are swapped together with the addresses when a
     reply is folded onto its request. Ingestion waits (up to 3 minutes) for the ISE SGT table and
     the first pxGrid context so that early flows are not attributed to `Unknown` for good.
     `/api/status` counts flow sides attributed from tags (`sgt_from_flow`) and unknown tag values
     (`unknown_tag`).
3. **Storage** (`matrix_advisor/store.py`, DuckDB).
   - `flow_minutes`: per-minute aggregates per (SGT pair, protocol, port, source IP, destination IP),
     7 days. Used for host counts and timing behaviour.
   - `pair_daily`: daily rollup per (SGT pair, protocol, port), `retention_days`.
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

1. **Kind** (deterministic): `external` if a side has no SGT; `extend` if the cell has a contract
   (the prefixed one if any); `reuse` if an existing SGACL covers all observed ports with at most two
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
   - `new`: create `<prefix><src>_to_<dst>`, add it to the cell;
   - `reuse` unchanged: add the existing SGACL to the cell;
   - changed existing contract, `clone`: create `<prefix><base>_<src>` and point only this cell to it;
   - changed existing contract, `inplace`: allowed only if the impact analysis (over the same retained
     history as the advisor) finds no observed traffic
     of another pair using the contract that would become denied; the SGACL is re-read and must not
     have changed since the proposal.
4. Create or update the cell: new cells get `MONITOR` or `ENABLED` per `write_mode`, existing cells
   keep their status. Reconcile, store the result and audit the decision.
