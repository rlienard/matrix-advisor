import { useCallback, useEffect, useMemo, useState } from "react";
import { get } from "../api";
import type { Dashboard as DashboardData, Link, Range, Status } from "../types";
import { KIND_LABEL, RISK, ago, fmt } from "../util";
import PairPanel from "./PairPanel";
import Sankey from "./Sankey";
import Trend from "./Trend";

const RANGES: { k: Range; label: string }[] = [
  { k: "24h", label: "24h" },
  { k: "7d", label: "7j" },
  { k: "30d", label: "30j" },
];

export default function Dashboard({ status }: { status: Status | null }) {
  const [range, setRange] = useState<Range>("7d");
  const [q, setQ] = useState("");
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

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
      {error && <div className="banner err">Chargement impossible : {error}</div>}
      {learning?.active && (
        <div className="banner">
          Phase d’apprentissage : l’agent observe sans rien proposer
          {learning.ends_at ? ` jusqu’au ${new Date(learning.ends_at + "Z").toLocaleString("fr-FR")}` : " (en attente des premiers flux)"}.
        </div>
      )}
      {!learning?.active && observation && observation.days > 0 && !observation.sufficient && (
        <div className="banner">
          {observation.retention_days < observation.recommended_days
            ? `Rétention de ${observation.retention_days} jours : un traitement mensuel peut sortir de l’historique avant d’avoir été revu. Passez la rétention à ${observation.recommended_days} jours au moins avant la bascule en default-deny.`
            : `${observation.days} jour(s) d’observation sur les ${observation.recommended_days} recommandés : un traitement mensuel peut ne pas encore avoir été vu. Attendez avant la bascule en default-deny.`}
        </div>
      )}
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "flex-end", gap: 12 }}>
        <div className="field" style={{ flex: "1 1 320px", maxWidth: 520 }}>
          <label className="field-label" htmlFor="flowSearch">Filtrer les flux</label>
          <input id="flowSearch" className="input" type="search" value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="SGT, port, protocole, contrat… ex. 443, HR, Web_Access" />
        </div>
        <div className="field">
          <span className="field-label">Période</span>
          <div className="segmented">
            {RANGES.map((r) => (
              <button key={r.k} type="button" aria-pressed={range === r.k} onClick={() => setRange(r.k)}>{r.label}</button>
            ))}
          </div>
        </div>
      </div>

      <div className="kpis">
        <div className="card kpi">
          <span className="label">Couverture de la matrice</span>
          <div style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}>
            <span className="value">{k?.coverage_pct ?? 0}%</span>
            <span className="mono small muted">{k?.allowed ?? 0}/{k?.pairs ?? 0} paires · {k?.partial ?? 0} partielle(s)</span>
          </div>
          <div className="bar"><div style={{ width: `${k?.coverage_pct ?? 0}%` }} /></div>
        </div>
        <div className="card kpi">
          <span className="label">Propositions en attente</span>
          <span className="value">{k?.pending ?? 0}</span>
          <span className="small muted">
            {(["extend", "reuse", "new", "external"] as const).filter((x) => byKind[x]).map((x) => `${byKind[x]} ${KIND_LABEL[x]}`).join(" · ") || "aucune"}
          </span>
        </div>
        <div className="card kpi">
          <span className="label">Flux bloqués si bascule maintenant</span>
          <span className="value">{fmt(k?.blocked_flows ?? 0)}</span>
          <span className="small muted">sur {fmt(k?.total_flows ?? 0)} observés</span>
        </div>
        <div className="card kpi">
          <span className="label">Propositions rejetées</span>
          <span className="value">{k?.rejected ?? 0}</span>
          <span className="small muted">resteront en deny</span>
        </div>
      </div>

      <div className="layout">
        <div className="main-col">
          <section className="card">
            <div className="card-head">
              <h2>Flux entre SGT</h2>
              <span className="small muted">Épaisseur = flux · cliquez un ruban pour le détail</span>
            </div>
            <Sankey links={links} selected={selected} matches={matches} onSelect={(id) => setSelected(id === selected ? null : id)} />
            <div className="legend">
              <span><span className="swatch" style={{ background: "var(--ok)" }} />Autorisé dans la matrice ISE</span>
              <span><span className="swatch" style={{ border: "1.5px dashed var(--pend)", background: "#3d2c17" }} />Partiellement couvert</span>
              <span><span className="swatch" style={{ background: "var(--pend)" }} />Non couvert</span>
              <span><span className="swatch" style={{ background: "var(--rej)" }} />Rejeté</span>
            </div>
          </section>

          <div className="row">
            <section className="card">
              <div className="card-head">
                <h2>Paires non couvertes</h2>
                <span className="mono small muted">{RANGES.find((r) => r.k === range)?.label}</span>
              </div>
              <p className="small muted" style={{ margin: 0 }}>Si la courbe descend, on converge vers le deny par défaut.</p>
              {data && learning && (
                <Trend points={data.trend} live={(k?.pairs ?? 0) - (k?.allowed ?? 0)} learning={learning}
                  rangeLabel={RANGES.find((r) => r.k === range)!.label} />
              )}
            </section>
            <section className="card">
              <div className="card-head">
                <h2>Bloqués si bascule maintenant</h2>
                <span className="mono small muted">{blocked.length} paires</span>
              </div>
              <p className="small muted" style={{ margin: 0 }}>Le filet de sécurité avant d’activer le deny par défaut.</p>
              <div>
                {blocked.map((l) => (
                  <button key={l.id} type="button" className="list-btn" onClick={() => setSelected(l.id)}>
                    <span className={l.status === "partial" ? "ring" : "sdot"}
                      style={l.status === "partial" ? undefined : { background: l.status === "rejected" ? "var(--rej)" : "var(--pend)" }} />
                    <span style={{ flexGrow: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                      <span style={{ fontSize: 13, fontWeight: 500 }}>{l.src} → {l.dst}</span>
                      <span className="mono" style={{ fontSize: 11, color: "var(--text-3)" }}>
                        {l.ports.filter((p) => !p.covered).map((p) => p.spec).join(" · ")}
                        {l.status === "partial" ? " (nouveau port)" : ""}
                      </span>
                    </span>
                    <span className="mono small" style={{ color: "var(--text-2)" }}>{fmt(l.blocked_flows)}</span>
                  </button>
                ))}
                {!blocked.length && <div className="empty">Rien ne serait bloqué sur cette période.</div>}
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
                <h2>Propositions en attente · {pending.length}</h2>
                <p className="small muted" style={{ margin: "4px 0 0" }}>
                  Regroupées par paire SGT, du plus gros volume au plus petit. L’agent réutilise ou étend un contrat existant avant d’en créer un nouveau.
                </p>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {pending.map((l) => (
                  <button key={l.id} type="button" className="prop-btn" onClick={() => setSelected(l.id)}>
                    <span style={{ display: "flex", alignItems: "center", gap: 8, width: "100%" }}>
                      <span className={l.status === "partial" ? "ring" : "sdot"} style={l.status === "partial" ? undefined : { background: "var(--pend)" }} />
                      <span style={{ flexGrow: 1, fontSize: 13, fontWeight: 600 }}>{l.src} → {l.dst}</span>
                      {l.risk && <span className={`chip ${RISK[l.risk].cls}`}>{RISK[l.risk].label}</span>}
                    </span>
                    <span style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", gap: 8, width: "100%", fontSize: 11 }}>
                      <span style={{ fontWeight: 600, color: "var(--info-fg)" }}>{l.kind ? KIND_LABEL[l.kind] : ""}</span>
                      <span className="mono muted">{l.ports.map((p) => p.spec).join(" · ")} · {fmt(l.flows)}</span>
                    </span>
                  </button>
                ))}
                {!pending.length && <div className="empty">Aucune proposition en attente{q ? " pour ce filtre" : ""}.</div>}
              </div>
              {status?.ise.last_sync && <span className="small muted">Matrice ISE lue {ago(status.ise.last_sync)}.</span>}
            </>
          )}
        </aside>
      </div>
    </>
  );
}
