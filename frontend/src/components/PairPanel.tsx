import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, get, post, put } from "../api";
import { normalize, parse, unobservedPermits, validate } from "../acl";
import { useI18n } from "../i18n";
import type { Analysis, Link, Proposal } from "../types";
import { RISK_CLS, STATUS_CLS } from "../util";

interface Props {
  link: Link;
  onClose: () => void;
  onChanged: () => void;
  onDecided: () => void; // approved or rejected: back to the pending list
}

interface Detail {
  proposal: Proposal;
  analysis: Analysis;
}

export default function PairPanel({ link, onClose, onChanged, onDecided }: Props) {
  const pid = link.proposal_id ?? link.last_decision_id;
  const [detail, setDetail] = useState<Detail | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [conflict, setConflict] = useState<string[] | null>(null);
  const { lang, m, fmt, shortDate } = useI18n();
  const t = m.pair;

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
  const check = useMemo(() => (p && p.kind !== "external" ? validate(text, p.specs, lang) : null), [text, p, lang]);
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
      onDecided();
    });
  const reject = () =>
    act(async () => {
      await post(`/proposals/${pid}/reject`);
      onDecided();
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
  let approveLabel = t.approve;
  let hint: { title: string; text: string } | null = null;
  if (p && a) {
    const base = p.base_contract ?? "";
    const others = a.others.map((o) => `${o.src} → ${o.dst}`).join(", ");
    if (p.kind === "new") {
      name = t.newName(a.new_name);
      aclTitle = t.newTitle;
      approveLabel = conflict ? t.mergeApprove : t.approve;
    } else if (p.kind === "unknown") {
      const fw = p.features.egress_firewall !== false;
      if (base) {
        name = t.unknownName(base);
        aclTitle = t.unknownTitle(base);
        approveLabel = t.assign(base);
      } else {
        name = t.newName(a.new_name);
        aclTitle = t.newTitle;
        approveLabel = conflict ? t.mergeApprove : t.approve;
      }
      hint = { title: t.unknownHintTitle(fw), text: t.unknownHint(fw) };
    } else if (p.kind === "reuse") {
      name = t.reuseName(base);
      aclTitle = t.reuseTitle(base);
      approveLabel = t.assign(base);
      const extra = unobservedPermits(parse(p.edited_acl ?? p.proposed_acl).rules, p.specs);
      hint = { title: t.reuseHintTitle, text: t.reuseHint(base, others, extra) };
    } else if (p.kind === "extend") {
      name = t.extendName(base);
      aclTitle = t.extendTitle(base);
      approveLabel = t.extend(base);
      hint = { title: t.extendHintTitle, text: t.extendHint(base, covered.join(", "), uncovered.join(", ")) };
    } else {
      name = t.externalName;
      hint = { title: t.externalHintTitle, text: t.externalHint };
    }
    if (isEdited && p.kind !== "external") approveLabel = t.approveEdited;
    if (sharedChoice) {
      if (cloned) {
        name = t.newContractName(a.clone_name!);
        aclTitle = `SGACL ${a.clone_name}`;
        approveLabel = t.createAndApprove(a.clone_name!);
        hint = { title: t.clonedFrom(base), text: t.cloneHint(base, a.clone_name!, others) };
      } else {
        name = t.changedForAllName(base);
        aclTitle = t.changedTitle(base);
        approveLabel = t.changeAndApprove(base);
        hint = null;
      }
    }
    if (editing) approveLabel = t.confirmEditFirst;
    // Once approved, show what was actually written in ISE.
    if (p.status === "approved" && p.result?.sgacl) {
      if (p.result.action === "clone") {
        name = t.newContractName(p.result.sgacl);
        aclTitle = `SGACL ${p.result.sgacl}`;
        hint = { title: t.clonedFrom(p.result.cloned_from!), text: t.unchangedForOthers(p.result.cloned_from!) };
      } else if (p.result.action === "create") {
        name = t.newName(p.result.sgacl);
        aclTitle = `SGACL ${p.result.sgacl}`;
      } else {
        name = `SGACL ${p.result.sgacl}`;
        aclTitle = `SGACL ${p.result.sgacl}`;
        if (p.kind === "reuse") hint = null;
      }
    }
  }

  const statusLabel = m.status[link.status];
  return (
    <>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 8 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 0 }}>
          {name && <span className="mono" style={{ fontSize: 11, color: "var(--text-3)" }}>{name}</span>}
          <h2 style={{ fontSize: 18, fontWeight: 700 }}>{link.src} → {link.dst}</h2>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            <span className={`chip ${p?.status === "approved" ? "ok" : STATUS_CLS[link.status]}`}>
              {p?.status === "approved" ? t.approved : statusLabel}{link.monitor ? " · monitor" : ""}
            </span>
            {p && <span className={`chip ${RISK_CLS[p.risk]}`}>{m.risk[p.risk]}</span>}
            {link.rare && (
              <span className="chip warn" title={t.rareTitle}>
                {t.rare}
              </span>
            )}
            {isEdited && <span className="chip info">{t.editedByAdmin}</span>}
            {p && !p.llm_used && pending && <span className="chip grey" title={t.heuristicTitle}>{t.heuristic}</span>}
          </div>
        </div>
        <button type="button" className="btn" onClick={onClose} aria-label={t.close} style={{ width: 44, padding: 0 }}>
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><path d="M3 3l10 10M13 3L3 13" /></svg>
        </button>
      </div>

      <div className="stat-grid">
        <div className="stat"><span>{t.flows}</span><span>{fmt(link.flows)}</span></div>
        <div className="stat"><span>{t.sourceHosts}</span><span>{fmt(link.hosts)}</span></div>
        <div className="stat"><span>{t.seenSince}</span><span>{shortDate(link.first_seen)}</span></div>
        <div className="stat" title={link.activity.last_seen_days_ago ? t.lastFlowDays(link.activity.last_seen_days_ago) : undefined}>
          <span>{t.activeDays}</span><span>{link.activity.days_seen} / {link.activity.observed_days}</span>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span className="section-label">{t.observedPorts}</span>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {link.ports.map((x) => (
            <span key={x.spec} className={`port ${link.status === "partial" && !x.covered ? "new" : ""}`} title={t.portTitle(fmt(x.flows), x.hosts)}>
              {x.spec}{link.status === "partial" ? (x.covered ? t.portCovered : t.portNew) : ""}
            </span>
          ))}
        </div>
      </div>

      {!pid && link.contracts.length > 0 && (
        <>
          {link.contracts.map((c) => (
            <div key={c.id} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <span className="section-label">{t.activeContract(c.name)}</span>
              <pre className="code">{c.acl}</pre>
              {c.shared_with.length > 0 && <span className="small muted">{t.alsoUsedBy(c.shared_with.join(", "))}</span>}
            </div>
          ))}
          <div className="box plain">{t.readFromIse}</div>
        </>
      )}

      {hint && (
        <div className="box info"><strong>{hint.title}</strong><span>{hint.text}</span></div>
      )}

      {p && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <span className="section-label">{t.justification}</span>
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
              <span className="small muted">{t.aceHelp}</span>
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
                {t.edit}
              </button>
              {isEdited && <button type="button" className="btn link" onClick={resetEdit}>{t.revert}</button>}
            </div>
          )}
          {pending && (editing || isEdited || invalid) && check && (
            <>
              {check.errors.map((t) => <div key={t} className="note err">{t}</div>)}
              {check.warns.map((t) => <div key={t} className="note warn">{t}</div>)}
              {check.infos.map((t) => <div key={t} className="note info">{t}</div>)}
              {!check.errors.length && !check.warns.length && !check.infos.length && (
                <div className="note ok">{t.valid}</div>
              )}
            </>
          )}
          {editing && (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              <button type="button" className="btn primary" disabled={invalid || busy} onClick={commitEdit}>{t.confirmEdit}</button>
              <button type="button" className="btn" onClick={() => setEditing(false)}>{t.cancel}</button>
            </div>
          )}
        </div>
      )}

      {sharedChoice && a && (
        <div className="box panel">
          <span className="section-label">{t.sharedTitle}</span>
          <span>
            {a.others.length
              ? t.sharedWith(a.base_contract!, a.others.length)
              : t.sharedNone(a.base_contract!)}
          </span>
          {a.others.map((o) => <span key={o.src + o.dst} className="mono small" style={{ color: "var(--text-2)" }}>{o.src} → {o.dst}</span>)}
          {a.impacts.map((i) => (
            <div key={i.src + i.dst + i.spec} className="note err">
              {t.impact(i.spec, i.src, i.dst, fmt(i.flows))}
            </div>
          ))}
          <div role="radiogroup" aria-label={t.howToApply} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <button type="button" role="radio" className="radio" aria-checked={mode === "clone"} onClick={() => setMode("clone")}>
              <span className="knob" />
              <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <strong style={{ fontSize: 13 }}>{t.cloneOption(a.clone_name!)}</strong>
                <span className="small muted">{t.cloneOptionHelp(a.base_contract!)}</span>
              </span>
            </button>
            <button type="button" role="radio" className="radio" aria-checked={mode === "inplace"} disabled={!a.inplace_allowed}
              onClick={() => setMode("inplace")}>
              <span className="knob" />
              <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <strong style={{ fontSize: 13 }}>{t.inplaceOption(a.base_contract!)}</strong>
                <span className="small muted">
                  {!a.inplace_allowed
                    ? t.inplaceBlocked
                    : a.others.length
                      ? t.inplaceShared
                      : t.inplaceAlone}
                </span>
              </span>
            </button>
          </div>
        </div>
      )}

      {conflict && (
        <div className="box bad">
          <strong>{t.conflictTitle}</strong>
          <span>{t.conflictText(conflict.join(", "))}</span>
        </div>
      )}
      {error && <div className="note err" role="alert">{error}</div>}

      {pending && p && (
        <>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {p.kind !== "external" && (
              <button type="button" className="btn ok grow" disabled={busy || editing || invalid} onClick={() => approve(!!conflict)}>
                {conflict ? t.mergeApprove : approveLabel}
              </button>
            )}
            <button type="button" className="btn grow" style={{ flex: "1 1 120px" }} disabled={busy} onClick={reject}>{t.reject}</button>
          </div>
          {p.kind !== "external" && (
            <p className="small muted" style={{ margin: 0 }}>
              {t.reread}{" "}
              {a?.write_mode === "enforce" ? t.writeEnforce : t.writeMonitor}
            </p>
          )}
        </>
      )}

      {p?.status === "approved" && (
        <div className="box plain">
          {t.approved} · {p.result?.action === "clone" ? t.resultClone(p.result.sgacl, p.result.cloned_from!) :
            p.result?.action === "create" ? t.resultCreate(p.result.sgacl) :
            p.result?.action === "assign" ? t.resultAssign(p.result.sgacl) : t.resultUpdate(p.result?.sgacl ?? "")}
          {" "}· {p.result?.cell_status === "MONITOR" ? t.cellMonitor : t.cellEnabled}.
          {isEdited ? t.editedFeedback : ""}
        </div>
      )}
      {p?.status === "rejected" && (
        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", justifyContent: "space-between", gap: 8 }} className="box plain">
          <span>{t.rejectedText}</span>
          <button type="button" className="btn" disabled={busy} onClick={reopen}>{t.reopen}</button>
        </div>
      )}

      <button type="button" className="btn link" style={{ alignSelf: "flex-start" }} onClick={onClose}>{t.back}</button>
    </>
  );
}
