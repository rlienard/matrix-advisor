import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, get, post, put } from "../api";
import { normalize, validate } from "../acl";
import type { Analysis, Link, Proposal } from "../types";
import { RISK, STATUS, fmt, shortDate } from "../util";

interface Props {
  link: Link;
  onClose: () => void;
  onChanged: () => void;
}

interface Detail {
  proposal: Proposal;
  analysis: Analysis;
}

export default function PairPanel({ link, onClose, onChanged }: Props) {
  const pid = link.proposal_id ?? link.last_decision_id;
  const [detail, setDetail] = useState<Detail | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [conflict, setConflict] = useState<string[] | null>(null);

  const load = useCallback(async () => {
    if (!pid) return setDetail(null);
    try {
      setDetail(await get<Detail>(`/proposals/${pid}`));
    } catch (e) {
      setError((e as Error).message);
    }
  }, [pid]);

  useEffect(() => {
    load();
  }, [load]);

  const p = detail?.proposal;
  const a = detail?.analysis;
  const pending = p?.status === "pending";
  const text = editing ? draft : p ? p.edited_acl ?? p.proposed_acl : "";
  const check = useMemo(() => (p && p.kind !== "external" ? validate(text, p.specs) : null), [text, p]);
  const invalid = !!check?.errors.length;
  const isEdited = !!p?.edited_acl;
  const sharedChoice = !!a && pending && !editing && a.changes_base && (isEdited || a.others.length > 0);
  const mode = a && !a.inplace_allowed ? "clone" : p?.mode ?? a?.default_mode ?? "clone";
  const cloned = sharedChoice && mode === "clone";
  const covered = link.ports.filter((x) => x.covered).map((x) => x.spec);
  const uncovered = link.ports.filter((x) => !x.covered).map((x) => x.spec);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      if (e instanceof ApiError && e.body?.conflict) setConflict((e.body.current_contracts as string[]) ?? []);
      else setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const commitEdit = () =>
    act(async () => {
      await put(`/proposals/${pid}/edit`, { acl: normalize(draft) === normalize(p!.proposed_acl) ? null : draft });
      setEditing(false);
      await load();
    });
  const resetEdit = () =>
    act(async () => {
      await put(`/proposals/${pid}/edit`, { acl: null });
      await load();
    });
  const setMode = (m: "clone" | "inplace") =>
    act(async () => {
      await put(`/proposals/${pid}/mode`, { mode: m });
      await load();
    });
  const approve = (merge = false) =>
    act(async () => {
      await post(`/proposals/${pid}/approve`, { mode: a?.changes_base ? mode : undefined, merge });
      setConflict(null);
      await load();
      onChanged();
    });
  const reject = () =>
    act(async () => {
      await post(`/proposals/${pid}/reject`);
      await load();
      onChanged();
    });
  const reopen = () =>
    act(async () => {
      await post(`/proposals/${pid}/reopen`);
      await load();
      onChanged();
    });

  // ---- labels
  let name = "";
  let aclTitle = "";
  let approveLabel = "Approuver";
  let hint: { title: string; text: string } | null = null;
  if (p && a) {
    const base = p.base_contract;
    const others = a.others.map((o) => `${o.src} → ${o.dst}`).join(", ");
    if (p.kind === "new") {
      name = `SGACL ${a.new_name} · créée par Matrix Advisor`;
      aclTitle = "Nouvelle SGACL proposée";
      approveLabel = conflict ? "Fusionner et approuver" : `Approuver en ${a.write_mode}`;
    } else if (p.kind === "reuse") {
      name = `SGACL ${base} · contrat existant réutilisé`;
      aclTitle = `Contrat réutilisé : ${base}`;
      approveLabel = `Assigner ${base}`;
      const extra = a.validation.infos.filter((i) => i.includes("jamais observé")).map((i) => i.split(" ")[0]);
      hint = {
        title: "Contrat existant réutilisable",
        text: `${base} est déjà assigné à ${others || "d’autres paires"}.` +
          (extra.length ? ` Il autorise aussi ${extra.join(", ")}, non observé ici : acceptable, ou modifiez-le (un clone sera créé).` : ""),
      };
    } else if (p.kind === "extend") {
      name = `SGACL ${base} · cellule existante dans ISE`;
      aclTitle = `Extension proposée de ${base}`;
      approveLabel = `Étendre ${base}`;
      hint = {
        title: "Contrat déjà présent dans la matrice ISE",
        text: `${base} autorise ${covered.join(", ") || "d’autres ports"} sur cette cellule. Seul ${uncovered.join(", ")} n’est pas couvert.`,
      };
    } else {
      name = "Hors matrice TrustSec";
      hint = {
        title: "Source ou destination sans SGT",
        text: "Une cellule TrustSec ne peut pas porter ce flux (Internet ou adresses non classées). Traitez-le sur le pare-feu de sortie, ou vérifiez l’affectation des endpoints dans ISE.",
      };
    }
    if (isEdited && p.kind !== "external") approveLabel = "Approuver la version modifiée";
    if (sharedChoice) {
      if (cloned) {
        name = `SGACL ${a.clone_name} · nouveau contrat`;
        aclTitle = `SGACL ${a.clone_name}`;
        approveLabel = `Créer ${a.clone_name} et approuver`;
        hint = {
          title: `Cloné à partir de : ${base}`,
          text: `${base} reste inchangé${others ? ` pour ${others}` : ""}. Seule cette paire utilisera ${a.clone_name}.`,
        };
      } else {
        name = `SGACL ${base} · modifié pour toutes les paires`;
        aclTitle = `${base} modifié`;
        approveLabel = `Modifier ${base} et approuver`;
        hint = null;
      }
    }
    if (editing) approveLabel = "Validez d’abord la modification";
    // Once approved, show what was actually written in ISE.
    if (p.status === "approved" && p.result?.sgacl) {
      if (p.result.action === "clone") {
        name = `SGACL ${p.result.sgacl} · nouveau contrat`;
        aclTitle = `SGACL ${p.result.sgacl}`;
        hint = { title: `Cloné à partir de : ${p.result.cloned_from}`, text: `${p.result.cloned_from} reste inchangé pour les autres paires.` };
      } else if (p.result.action === "create") {
        name = `SGACL ${p.result.sgacl} · créée par Matrix Advisor`;
        aclTitle = `SGACL ${p.result.sgacl}`;
      } else {
        name = `SGACL ${p.result.sgacl}`;
        aclTitle = `SGACL ${p.result.sgacl}`;
        if (p.kind === "reuse") hint = null;
      }
    }
  }

  const statusChip = STATUS[link.status];
  return (
    <>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 0 }}>
          {name && <span className="mono" style={{ fontSize: 11, color: "var(--text-3)" }}>{name}</span>}
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>{link.src} → {link.dst}</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            <span className={`chip ${p?.status === "approved" ? "ok" : statusChip.cls}`}>
              {p?.status === "approved" ? "Approuvé" : statusChip.label}{link.monitor ? " · monitor" : ""}
            </span>
            {p && <span className={`chip ${RISK[p.risk].cls}`}>{RISK[p.risk].label}</span>}
            {link.rare && (
              <span className="chip warn" title="Peu de jours d’activité : traitement périodique possible, dont tous les ports n’ont peut-être pas été vus">
                Flux rare
              </span>
            )}
            {isEdited && <span className="chip info">Modifié par l’admin</span>}
            {p && !p.llm_used && pending && <span className="chip grey" title="Le modèle n’a pas répondu : analyse heuristique">Heuristique</span>}
          </div>
        </div>
        <button type="button" className="btn" onClick={onClose} aria-label="Fermer le détail" style={{ width: 44, padding: 0 }}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M3 3l10 10M13 3L3 13" /></svg>
        </button>
      </div>

      <div className="stat-grid">
        <div className="stat"><span>Flux</span><span>{fmt(link.flows)}</span></div>
        <div className="stat"><span>Hôtes source</span><span>{fmt(link.hosts)}</span></div>
        <div className="stat"><span>Vu depuis</span><span>{shortDate(link.first_seen)}</span></div>
        <div className="stat" title={link.activity.last_seen_days_ago ? `Dernier flux il y a ${link.activity.last_seen_days_ago} jour(s)` : undefined}>
          <span>Jours d’activité</span><span>{link.activity.days_seen} / {link.activity.observed_days}</span>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span className="section-label">Ports observés</span>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {link.ports.map((x) => (
            <span key={x.spec} className={`port ${link.status === "partial" && !x.covered ? "new" : ""}`} title={`${fmt(x.flows)} flux · ${x.hosts} hôte(s)`}>
              {x.spec}{link.status === "partial" ? (x.covered ? " · couvert" : " · nouveau") : ""}
            </span>
          ))}
        </div>
      </div>

      {!pid && link.contracts.length > 0 && (
        <>
          {link.contracts.map((c) => (
            <div key={c.id} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <span className="section-label">Contrat actif : {c.name}</span>
              <pre className="code">{c.acl}</pre>
              {c.shared_with.length > 0 && <span className="small muted">Aussi utilisé par {c.shared_with.join(", ")}.</span>}
            </div>
          ))}
          <div className="box plain">Contrat lu dans la matrice ISE. L’agent surveille l’apparition de nouveaux ports sur cette paire.</div>
        </>
      )}

      {hint && (
        <div className="box info"><strong>{hint.title}</strong><span>{hint.text}</span></div>
      )}

      {p && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <span className="section-label">Justification de l’agent</span>
          <p style={{ margin: 0, fontSize: 13 }}>{p.justification}</p>
        </div>
      )}

      {p && p.kind !== "external" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <span className="section-label">{aclTitle}</span>
          {editing ? (
            <>
              <textarea className={`code ${invalid ? "invalid" : "edited"}`} aria-label={aclTitle} value={draft} spellCheck={false}
                rows={Math.max(4, draft.split("\n").length + 1)} onChange={(e) => setDraft(e.target.value)} />
              <span className="small muted">Une ACE par ligne : permit|deny tcp|udp|icmp|ip [dst eq N | dst range N M] [log] · « + » marque une ligne ajoutée</span>
            </>
          ) : (
            <pre className="code">{text}</pre>
          )}
          {pending && !editing && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              <button type="button" className="btn" disabled={busy} onClick={() => { setDraft(text); setEditing(true); }}>
                <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M11 2.5l2.5 2.5L5.5 13H3v-2.5z" /><path d="M9.5 4l2.5 2.5" />
                </svg>
                Modifier
              </button>
              {isEdited && <button type="button" className="btn link" onClick={resetEdit}>Revenir à la proposition de l’agent</button>}
            </div>
          )}
          {pending && (editing || isEdited || invalid) && check && (
            <>
              {check.errors.map((t) => <div key={t} className="note err">{t}</div>)}
              {check.warns.map((t) => <div key={t} className="note warn">{t}</div>)}
              {check.infos.map((t) => <div key={t} className="note info">{t}</div>)}
              {!check.errors.length && !check.warns.length && !check.infos.length && (
                <div className="note ok">Syntaxe valide · tous les ports observés restent autorisés.</div>
              )}
            </>
          )}
          {editing && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              <button type="button" className="btn primary" disabled={invalid || busy} onClick={commitEdit}>Valider la modification</button>
              <button type="button" className="btn" onClick={() => setEditing(false)}>Annuler</button>
            </div>
          )}
        </div>
      )}

      {sharedChoice && a && (
        <div className="box panel">
          <span className="section-label">Contrat partagé · analyse d’impact</span>
          <span>
            {a.others.length
              ? `${a.base_contract} est aussi utilisé par ${a.others.length} autre${a.others.length > 1 ? "s paires" : " paire"} :`
              : `${a.base_contract} n’est utilisé par aucune autre paire.`}
          </span>
          {a.others.map((o) => <span key={o.src + o.dst} className="mono small" style={{ color: "var(--text-2)" }}>{o.src} → {o.dst}</span>)}
          {a.impacts.map((i) => (
            <div key={i.src + i.dst + i.spec} className="note err">
              {i.spec} utilisé par {i.src} → {i.dst} ({fmt(i.flows)} flux) ne serait plus autorisé.
            </div>
          ))}
          <div role="radiogroup" aria-label="Comment appliquer la modification" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <button type="button" role="radio" className="radio" aria-checked={mode === "clone"} onClick={() => setMode("clone")}>
              <span className="knob" />
              <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <strong style={{ fontSize: 13 }}>Cloner en {a.clone_name} (recommandé)</strong>
                <span className="small muted">{a.base_contract} reste intact. Seule cette paire utilise la copie modifiée.</span>
              </span>
            </button>
            <button type="button" role="radio" className="radio" aria-checked={mode === "inplace"} disabled={!a.inplace_allowed}
              onClick={() => setMode("inplace")}>
              <span className="knob" />
              <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <strong style={{ fontSize: 13 }}>Modifier {a.base_contract} directement</strong>
                <span className="small muted">
                  {!a.inplace_allowed
                    ? "Bloqué : la modification casserait du trafic légitime d’autres paires."
                    : a.others.length
                      ? "Aucun flux observé des autres paires n’est affecté, mais vos ajouts s’appliqueront aussi à elles."
                      : "Sans impact : aucune autre paire n’utilise ce contrat aujourd’hui."}
                </span>
              </span>
            </button>
          </div>
        </div>
      )}

      {conflict && (
        <div className="box bad">
          <strong>Conflit détecté à la relecture d’ISE · rien n’a été écrit</strong>
          <span>
            La cellule a été modifiée dans ISE depuis la proposition{conflict.length ? ` (contrats actuels : ${conflict.join(", ")})` : ""}.
            L’agent ne l’écrase pas : sa SGACL peut être ajoutée à côté, sans toucher aux contrats existants.
          </span>
        </div>
      )}
      {error && <div className="note err" role="alert">{error}</div>}

      {pending && p && (
        <>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {p.kind !== "external" && (
              <button type="button" className="btn ok grow" disabled={busy || editing || invalid} onClick={() => approve(!!conflict)}>
                {conflict ? "Fusionner et approuver" : approveLabel}
              </button>
            )}
            <button type="button" className="btn grow" style={{ flex: "1 1 120px" }} disabled={busy} onClick={reject}>Rejeter</button>
          </div>
          {p.kind !== "external" && (
            <p className="small muted" style={{ margin: 0 }}>
              La cellule est relue dans ISE juste avant l’écriture.{" "}
              {a?.write_mode === "enforce" ? "Nouvelle cellule écrite en mode enforce." : "Nouvelle cellule écrite en mode monitor (log, pas de blocage)."}
            </p>
          )}
        </>
      )}

      {p?.status === "approved" && (
        <div className="box plain">
          Approuvé · {p.result?.action === "clone" ? `${p.result.sgacl} créé (cloné à partir de ${p.result.cloned_from})` :
            p.result?.action === "create" ? `${p.result.sgacl} créé` :
            p.result?.action === "assign" ? `${p.result.sgacl} assigné à la cellule` : `${p.result?.sgacl} mis à jour`}
          {" "}· cellule {p.result?.cell_status === "MONITOR" ? "en monitor" : "active"}.
          {isEdited ? " Version modifiée par l’admin, enregistrée comme retour pour l’agent." : ""}
        </div>
      )}
      {p?.status === "rejected" && (
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: 8 }} className="box plain">
          <span>Proposition rejetée : la paire reste en deny.</span>
          <button type="button" className="btn" disabled={busy} onClick={reopen}>Rouvrir</button>
        </div>
      )}

      <button type="button" className="btn link" style={{ alignSelf: "flex-start" }} onClick={onClose}>← Toutes les propositions</button>
    </>
  );
}
