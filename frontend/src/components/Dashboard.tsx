import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, get, post } from "../api";
import type { Dashboard as DashboardData, Link, Range, Status } from "../types";
import { useI18n } from "../i18n";
import { RISK_CLS } from "../util";
import PairPanel from "./PairPanel";
import Sankey, { STATUS_COLOR } from "./Sankey";
import Trend from "./Trend";

const RANGES: Range[] = ["24h", "7d", "30d"];

export default function Dashboard({ status }: { status: Status | null }) {
  const [range, setRange] = useState<Range>("7d");
  const [q, setQ] = useState("");
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [selMode, setSelMode] = useState(false);
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [bulk, setBulk] = useState<{ busy: boolean; text: string; tone: "ok" | "warn" | "info" } | null>(null);
  const { m, fmt, ago, dateTime } = useI18n();
  const d = m.dash;

  const load = useCallback(() => {
    get<DashboardData>(`/dashboard?range=${range}`)
      .then((d) => {
        setData(d);
        setError("");
      })
      .catch((e) => setError(e.message));
  }, [range]);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const matches = useCallback(
    (l: Link) => {
      const needle = q.trim().toLowerCase();
      if (!needle) return true;
      const hay = [l.src, l.dst, ...l.ports.map((p) => p.spec), ...l.contracts.map((c) => c.name)].join(" ").toLowerCase();
      return hay.includes(needle);
    },
    [q],
  );

  const links = data?.links ?? [];
  const pending = useMemo(
    () => links.filter((l) => l.proposal_id && matches(l)).sort((a, b) => b.flows - a.flows),
    [links, matches],
  );
  const blocked = useMemo(
    () => links.filter((l) => l.status !== "allowed" && matches(l)).sort((a, b) => b.blocked_flows - a.blocked_flows),
    [links, matches],
  );
  const current = links.find((l) => l.id === selected) ?? null;
  const k = data?.kpi;
  const byKind = k?.pending_by_kind ?? {};
  const learning = data?.learning ?? status?.learning;
  const observation = data?.observation ?? status?.observation;
  const pickedIds = pending.filter((l) => picked[l.id]).map((l) => l.id);
  const allPicked = pending.length > 0 && pickedIds.length === pending.length;

  // Bulk decisions go through the same endpoints as single ones, one proposal at a time: each
  // approval re-reads its cell in ISE; a conflict or an error skips that proposal only.
  async function decideBulk(action: "approve" | "reject") {
    const chosen = pending.filter((l) => picked[l.id] && l.proposal_id);
    if (!chosen.length) return;
    let done = 0;
    const skipped: string[] = [];
    for (const l of chosen) {
      setBulk({ busy: true, text: d.bulkRunning(done, chosen.length), tone: "info" });
      try {
        if (action === "approve" && l.kind === "external") throw new Error("external");
        await post(`/proposals/${l.proposal_id}/${action}`, action === "approve" ? {} : undefined);
        done++;
      } catch (e) {
        skipped.push(`${l.src} → ${l.dst}${e instanceof ApiError && !e.body?.conflict ? ` (${e.message})` : ""}`);
      }
    }
    setPicked({});
    setSelMode(false);
    const text = (done ? (action === "approve" ? d.bulkDone(done, 0) : d.bulkDone(0, done)) : "") +
      (skipped.length ? d.bulkSkipped(skipped.join(", ")) : "");
    setBulk({ busy: false, text: text.trim(), tone: skipped.length ? "warn" : "ok" });
    load();
  }

  const down = {
    collector: status ? !status.netflow.online : false,
    ise: status ? !status.ise.online : false,
    llm: status?.llm.online === false,
  };

  return (
    <>
      {error && <div className="banner err">{d.loadError(error)}</div>}
      {learning?.active && (
        <div className="banner">
          {d.learning(learning.ends_at ? dateTime(learning.ends_at) : null)}
        </div>
      )}
      {!learning?.active && observation && observation.days > 0 && !observation.sufficient && (
        <div className="banner">
          {observation.retention_days < observation.recommended_days
            ? d.retentionTooShort(observation.retention_days, observation.recommended_days)
            : d.observationTooShort(observation.days, observation.recommended_days)}
        </div>
      )}
      {down.collector && status && <div className="banner">{d.collectorDown(status.netflow.stale_after_seconds)}</div>}
      {down.ise && status && <div className="banner">{d.iseDown(ago(status.ise.last_sync))}</div>}
      {down.llm && status && <div className="banner">{d.llmDown(status.llm.timeout_s)}</div>}
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-end", gap: 12 }}>
        <div className="field" style={{ flex: "1 1 320px", maxWidth: 520 }}>
          <label className="field-label" htmlFor="flowSearch">{d.filter}</label>
          <input id="flowSearch" className="input" type="search" value={q} onChange={(e) => setQ(e.target.value)}
            placeholder={d.filterPlaceholder} />
        </div>
        <div className="field">
          <span className="field-label">{d.period}</span>
          <div className="segmented">
            {RANGES.map((r) => (
              <button key={r} type="button" aria-pressed={range === r} onClick={() => setRange(r)}>{d.ranges[r]}</button>
            ))}
          </div>
        </div>
      </div>

      <div className="kpis">
        <div className="card kpi">
          <span className="label">{d.coverage}</span>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
            <span className="value">{k?.coverage_pct ?? 0}%</span>
            <span className="mono small muted">{d.coverageDetail(k?.allowed ?? 0, k?.pairs ?? 0, k?.partial ?? 0)}</span>
          </div>
          <div className="bar"><div style={{ width: `${k?.coverage_pct ?? 0}%` }} /></div>
        </div>
        <div className="card kpi">
          <span className="label">{d.pending}</span>
          <span className="value">{k?.pending ?? 0}</span>
          <span className="small muted">
            {(["extend", "reuse", "new", "unknown", "external"] as const).filter((x) => byKind[x]).map((x) => `${byKind[x]} ${m.kind[x]}`).join(" · ") || d.none}
          </span>
        </div>
        <div className="card kpi">
          <span className="label">{d.blocked}</span>
          <span className="value">{fmt(k?.blocked_flows ?? 0)}</span>
          <span className="small muted">{d.outOf(fmt(k?.total_flows ?? 0))}</span>
        </div>
        <div className="card kpi">
          <span className="label">{d.rejected}</span>
          <span className="value">{k?.rejected ?? 0}</span>
          <span className="small muted">{d.staysDenied}</span>
        </div>
      </div>

      <div className="layout">
        <div className="main-col">
          <section className="card">
            <div className="card-head">
              <h2>{d.sankey}</h2>
              <span className="small muted">{d.sankeyHint}</span>
            </div>
            <Sankey links={links} selected={selected} matches={matches} onSelect={(id) => setSelected(id === selected ? null : id)} />
            <div className="legend">
              <span><span className="swatch" style={{ background: STATUS_COLOR.allowed }} />{d.legendAllowed}</span>
              <span><span className="swatch" style={{ border: "1.5px dashed var(--part)", background: STATUS_COLOR.partial }} />{m.status.partial}</span>
              <span><span className="swatch" style={{ background: STATUS_COLOR.pending }} />{m.status.pending}</span>
              <span><span className="swatch" style={{ background: STATUS_COLOR.rejected }} />{m.status.rejected}</span>
            </div>
          </section>

          <div className="row">
            <section className="card">
              <div className="card-head">
                <h2>{d.uncovered}</h2>
                <span className="mono small muted">{d.ranges[range]}</span>
              </div>
              <p className="small muted" style={{ margin: 0 }}>{d.uncoveredHint}</p>
              {data && learning && (
                <Trend points={data.trend} live={(k?.pairs ?? 0) - (k?.allowed ?? 0)} learning={learning}
                  rangeLabel={d.ranges[range]} />
              )}
            </section>
            <section className="card">
              <div className="card-head">
                <h2>{d.blockedNow}</h2>
                <span className="mono small muted">{d.pairs(blocked.length)}</span>
              </div>
              <p className="small muted" style={{ margin: 0 }}>{d.blockedHint}</p>
              <div>
                {blocked.map((l) => (
                  <button key={l.id} type="button" className="list-btn" onClick={() => setSelected(l.id)}>
                    <span className={l.status === "partial" ? "ring" : "sdot"}
                      style={l.status === "partial" ? undefined : { background: STATUS_COLOR[l.status] }} />
                    <span style={{ flexGrow: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                      <span style={{ fontSize: 13, fontWeight: 500 }}>{l.src} → {l.dst}</span>
                      <span className="mono" style={{ fontSize: 11, color: "var(--text-3)" }}>
                        {l.ports.filter((p) => !p.covered).map((p) => p.spec).join(" · ")}
                        {l.status === "partial" ? d.newPort : ""}
                      </span>
                    </span>
                    <span className="mono small" style={{ color: "var(--text-2)" }}>{fmt(l.blocked_flows)}</span>
                  </button>
                ))}
                {!blocked.length && <div className="empty">{d.nothingBlocked}</div>}
              </div>
            </section>
          </div>
        </div>

        <aside className="card side">
          {current ? (
            <PairPanel key={current.id} link={current} onClose={() => setSelected(null)} onChanged={load}
              onDecided={() => {
                setSelected(null);
                load();
              }} />
          ) : (
            <>
              <div>
                <h2>{d.pendingCount(pending.length)}</h2>
                <p className="small muted" style={{ margin: "4px 0 0" }}>
                  {d.pendingHint}
                </p>
              </div>
              {selMode && pending.length > 0 && (
                <label className="pick-all" htmlFor="pickAll">
                  <input id="pickAll" type="checkbox" checked={allPicked} aria-describedby="pickCount"
                    onChange={() => setPicked(allPicked ? {} : Object.fromEntries(pending.map((l) => [l.id, true])))} />
                  <span style={{ flexGrow: 1 }}>{d.selectAll}</span>
                  <span id="pickCount" className="mono small muted" style={{ fontWeight: 400 }}>{d.picked(pickedIds.length, pending.length)}</span>
                </label>
              )}
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {pending.map((l) => {
                  const head = (
                    <>
                      <span style={{ display: "flex", alignItems: "center", gap: 8, width: "100%" }}>
                        <span className={l.status === "partial" ? "ring" : "sdot"} style={l.status === "partial" ? undefined : { background: STATUS_COLOR.pending }} />
                        <span style={{ flexGrow: 1, fontSize: 13, fontWeight: 600 }}>{l.src} → {l.dst}</span>
                        {l.risk && <span className={`chip ${RISK_CLS[l.risk]}`}>{m.risk[l.risk]}</span>}
                      </span>
                      <span style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", gap: 8, width: "100%", fontSize: 11 }}>
                        <span style={{ fontWeight: 600, color: "var(--info-fg)" }}>{l.kind ? m.kind[l.kind] : ""}</span>
                        <span className="mono muted">{l.ports.map((p) => p.spec).join(" · ")} · {fmt(l.flows)}</span>
                      </span>
                    </>
                  );
                  if (!selMode) {
                    return <button key={l.id} type="button" className="prop-btn" onClick={() => setSelected(l.id)}>{head}</button>;
                  }
                  const id = "pick-" + l.id.replace(/[^A-Za-z0-9_-]/g, "_");
                  return (
                    <label key={l.id} htmlFor={id} className={`pick-row ${picked[l.id] ? "on" : ""}`}>
                      <input id={id} type="checkbox" checked={!!picked[l.id]}
                        onChange={() => setPicked((x) => ({ ...x, [l.id]: !x[l.id] }))} />
                      <span style={{ flexGrow: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 6 }}>{head}</span>
                    </label>
                  );
                })}
                {!pending.length && <div className="empty">{d.noPending(!!q)}</div>}
              </div>
              {bulk && <div role="status" className={`note ${bulk.tone}`} style={{ fontSize: 13 }}>{bulk.text}</div>}
              {pending.length > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8 }}>
                  <button type="button" className="btn" aria-pressed={selMode} disabled={bulk?.busy}
                    onClick={() => { setSelMode(!selMode); setPicked({}); setBulk(null); }}>
                    {selMode ? d.cancelSelect : d.select}
                  </button>
                  <span style={{ flexGrow: 1 }} />
                  {selMode && (
                    <>
                      <button type="button" className="btn ok" disabled={!pickedIds.length || bulk?.busy} onClick={() => decideBulk("approve")}>
                        {d.approveN(pickedIds.length)}
                      </button>
                      <button type="button" className="btn" disabled={!pickedIds.length || bulk?.busy} onClick={() => decideBulk("reject")}>
                        {d.rejectN(pickedIds.length)}
                      </button>
                    </>
                  )}
                </div>
              )}
            </>
          )}
        </aside>
      </div>
    </>
  );
}
