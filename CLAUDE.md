# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

Matrix Advisor proposes Cisco TrustSec SGACL contracts from observed NetFlow/IPFIX traffic so that an
SD-Access matrix can be switched to default-deny without breaking legitimate flows. A human approves
every change before it is written to Cisco ISE. Companion demo of the Cisco Live session BRKENS-3810
("How to Adopt Zero Trust using SD-Access and Default-Deny without Tears", Raphael Lienard).

Data path: switches → GoFlow2 (JSON file) → ingest (orient flows, IP → SGT) → DuckDB aggregates
(+ Parquet archive of raw flows) → advisor (coverage vs ISE matrix, extend/reuse/new) → LLM (risk +
justification) → FastAPI → React UI → approval → re-read cell → write to ISE.
Details: `docs/architecture.md`. Session context and design history: README and this file.

## Layout

```
backend/matrix_advisor/
  config.py            YAML config + secrets (env vars > secrets.json 0600); never write secrets to YAML
  store.py             DuckDB schema and queries (flow_minutes 7 days, pair_daily, proposals, audit)
  ingest/              goflow.py (tail NDJSON, orient), resolver.py (IP→SGT), pipeline.py (loop)
  ise/                 client.py (ERS + OpenAPI), pxgrid.py (pxGrid 2.0 + STOMP), service.py (cache, reconcile)
  policy/              acl.py (SGACL parse/validate), matrix.py (coverage), impact.py (shared-contract impact)
  agent/               advisor.py (proposals), risk.py (heuristics), llm.py (providers + IP guard), prompts.py,
                       actions.py (approve/reject/edit and ISE writes)
  api/                 routes.py (REST), auth.py (single admin, signed cookie)
  main.py              wiring, background workers, static UI
backend/tests/         pytest; test_workflow.py runs the full flow against the ISE simulator, test_pxgrid_ws.py the
                       STOMP subscription; fixtures/acl_parity.json is shared with frontend/tests
frontend/src/          React + TS: components/{Dashboard,Sankey,Trend,PairPanel,Settings,Header,Login}.tsx,
                       acl.ts mirrors policy/acl.py for live feedback
simulators/ise_sim/    fake ISE (ERS, deployment nodes, pxGrid REST + STOMP pubsub, /sim/conflict|session|reset|state)
simulators/flowgen/    IPFIX generator with the demo scenarios (no dependencies; --sgt adds CTS group tags)
deploy/                config templates (example, demo, lima), goflow2/mapping.yaml, lima/lima-demo.sh
```

## Commands

```bash
# backend
cd backend && pip install -e ".[dev]"
pytest -q                                  # must stay green
ruff check matrix_advisor tests ../simulators
MA_CONFIG=/path/to/config.yaml matrix-advisor   # API on :8000 (MA_STATIC_DIR=frontend/dist to serve the UI)

# frontend (dev server proxies /api to :8000)
cd frontend && npm install && npm run dev
npm run build                              # runs tsc -b, must type-check
npm test                                   # acl.ts parity cases (shared with backend/tests/fixtures/acl_parity.json)

# local end-to-end without Docker
cd simulators/ise_sim && uvicorn ise_sim:app --port 9060
goflow2 -listen netflow://:4739 -format json -transport file -transport.file /tmp/goflow2.ndjson \
  -mapping deploy/goflow2/mapping.yaml
python simulators/flowgen/flowgen.py --collector 127.0.0.1:4739 --speed 5
# config: openapi.base_url / pxgrid.base_url = http://127.0.0.1:9060, learning_days: 0,
#         collector.input_file = /tmp/goflow2.ndjson, allowed_exporters: [127.0.0.0/8]

# Docker demo
MA_CONFIG_TEMPLATE=/app/deploy/config.demo.yaml docker compose --profile demo --profile llm up -d --build
# macOS + Lima: ./deploy/lima/lima-demo.sh (Ollama runs natively on the Mac, reached via host.lima.internal)
```

## Invariants (do not break)

- **No IP address ever reaches the LLM.** IP → SGT resolution happens before the advisor; prompts carry
  SGT names, ports, counts and timing only. `llm.assert_no_ip` must run on every payload. `send_ip_addresses`
  is `Literal[False]` on purpose.
- **ISE is the source of truth.** The matrix cache is rebuilt from ISE (periodic, on pxGrid notification,
  after each write). Never trust the cache for a write: `actions.approve` re-reads the cell and compares its
  fingerprint with the one stored at proposal time; on mismatch return 409 and write nothing unless `merge`.
- **Shared contracts:** changing an existing SGACL defaults to a clone (`<prefix><base>_<src>`); in-place
  modification only when `impact_of_change` finds no observed traffic of another pair that would be denied.
- **Cell status:** new cells get `MONITOR` (write_mode monitor) or `ENABLED` (enforce); existing cells keep
  their status. Never downgrade an enforced cell.
- **Heuristic risk is a floor:** the LLM can raise risk, never lower it. If the LLM fails, keep the heuristic
  proposal (the app must work with no LLM at all).
- **Ownership:** created/cloned SGACLs carry `ise.sgacl_prefix` (default `MA_`); every decision is audited.
- **Secrets:** never in YAML, logs, API responses (masked as `********`) or the LLM payload.
- **No silent writes:** nothing is written to ISE without an explicit approval from the UI/API.

## Conventions

- Code, comments, README, commit messages: **English**. UI strings and user-facing API error messages:
  **French** (e.g. « Hors ligne » without hyphen, « En ligne », « Cisco ISE : En ligne (synchro …) »).
- Keep `frontend/src/acl.ts` and `backend/matrix_advisor/policy/acl.py` behaviourally identical; a change to either
  needs a case in `backend/tests/fixtures/acl_parity.json`, which both test suites assert.
- UI look: dark theme inspired by Cisco Cloud Control (Magnetic `onecd-dark` tokens in `styles.css`:
  page `#0F1214`, card `#171B20`, primary `#649EF5`, ok `#4CBF7F`, Inter). No Cisco logo or product name:
  this is not an official Cisco product.
- UX decisions already validated with the author: SGACL editor locked by default ("Modifier" →
  "Valider la modification" / "Annuler"); approve disabled while editing; the clone/in-place choice appears
  only after "Valider la modification"; once cloned, show the clone name with « Cloné à partir de : … ».
- Add a test for every behaviour change in `policy/`, `agent/actions.py` or the API.
- Python 3.11+, line length 110, ruff clean. TypeScript strict, no unused locals.

## Known gaps / to verify against a real ISE

- ERS paths and JSON wrappers (`Sgt`, `Sgacl`, `EgressMatrixCell`), `/api/v1/deployment/node`, pxGrid control
  and REST calls were written from knowledge of ISE 3.x, not checked against official docs: validate in a lab.
- pxGrid websocket (STOMP) subscription is tested only against the simulator, whose topics and message bodies are
  approximations (SGACL and egress cell changes share `securityGroupAclTopic`): check frames on a real ISE.
- ISE staging matrix / workflow mode is not driven by the API (`write_mode: monitor` is the substitute);
  policy push to devices is left to the ISE admin.
- GoFlow2 has no Parquet output (JSON/protobuf only); the backend writes Parquet itself.
- SGT in flow records: `deploy/goflow2/mapping.yaml` assumes NetFlow v9 fields 34000/34001 and IPFIX
  enterprise elements 1232/1233 with PEN 9 (verified with flowgen `--sgt` + GoFlow2 2.2.7 only): capture
  a real switch export to confirm.
- Docker images and the Lima script have not been built/run yet; check arm64 availability of
  `netsampler/goflow2` on Apple Silicon.
- Roadmap: multiple matrices, i18n.
