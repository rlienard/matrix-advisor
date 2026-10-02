import { useCallback, useEffect, useMemo, useState } from "react";
import { get } from "../api";
import type { Dashboard as DashboardData, Link, Range, Status } from "../types";
import { useI18n } from "../i18n";
import { RISK_CLS } from "../util";
import PairPanel from "./PairPanel";
import Sankey from "./Sankey";
import Trend from "./Trend";

const RANGES: Range[] = ["24h", "7d", "30d"];

export default function Dashboard({ status }: { status: Status | null }) {
  const [range, setRange] = useState<Range>("7d");
  const [q, setQ] = useState("");
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
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
            {(["extend", "reuse", "new", "external"] as const).filter((x) => byKind[x]).map((x) => `${byKind[x]} ${m.kind[x]}`).join(" · ") || d.none}
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
              <span><span className="swatch" style={{ background: "var(--ok)" }} />{d.legendAllowed}</span>
              <span><span className="swatch" style={{ border: "1.5px dashed var(--pend)", background: "#3d2c17" }} />{m.status.partial}</span>
              <span><span className="swatch" style={{ background: "var(--pend)" }} />{m.status.pending}</span>
              <span><span className="swatch" style={{ background: "var(--rej)" }} />{m.status.rejected}</span>
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
                      style={l.status === "partial" ? undefined : { background: l.status === "rejected" ? "var(--rej)" : "var(--pend)" }} />
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
            <PairPanel key={current.id} link={current} onClose={() => setSelected(null)} onChanged={load} />
          ) : (
            <>
              <div>
                <h2>{d.pendingCount(pending.length)}</h2>
                <p className="small muted" style={{ margin: "4px 0 0" }}>
                  {d.pendingHint}
                </p>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {pending.map((l) => (
                  <button key={l.id} type="button" className="prop-btn" onClick={() => setSelected(l.id)}>
                    <span style={{ display: "flex", alignItems: "center", gap: 8, width: "100%" }}>
                      <span className={l.status === "partial" ? "ring" : "sdot"} style={l.status === "partial" ? undefined : { background: "var(--pend)" }} />
                      <span style={{ flexGrow: 1, fontSize: 13, fontWeight: 600 }}>{l.src} → {l.dst}</span>
                      {l.risk && <span className={`chip ${RISK_CLS[l.risk]}`}>{m.risk[l.risk]}</span>}
                    </span>
                    <span style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", gap: 8, width: "100%", fontSize: 11 }}>
                      <span style={{ fontWeight: 600, color: "var(--info-fg)" }}>{l.kind ? m.kind[l.kind] : ""}</span>
                      <span className="mono muted">{l.ports.map((p) => p.spec).join(" · ")} · {fmt(l.flows)}</span>
                    </span>
                  </button>
                ))}
                {!pending.length && <div className="empty">{d.noPending(!!q)}</div>}
              </div>
              {status?.ise.last_sync && <span className="small muted">{d.matrixRead(ago(status.ise.last_sync))}</span>}
            </>
          )}
        </aside>
      </div>
    </>
  );
}
