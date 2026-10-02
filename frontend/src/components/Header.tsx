import type { Status } from "../types";
import { ago } from "../util";

interface Props {
  status: Status | null;
  view: "dash" | "settings";
  onToggleView: () => void;
  onResync: () => void;
  onLogout: () => void;
}

function Dot({ on }: { on: boolean | null | undefined }) {
  return <span className={`dot ${on === null || on === undefined ? "" : on ? "on" : "off"}`} />;
}

export default function Header({ status, view, onToggleView, onResync, onLogout }: Props) {
  const ise = status?.ise;
  const llm = status?.llm;
  const nf = status?.netflow;
  return (
    <header className="header">
      <div className="brand">
        <h1>Matrix Advisor</h1>
        <span className="tag">SD-Access · Default-Deny</span>
        <p>Flux observés entre SGT et contrats SGACL proposés par l’agent</p>
      </div>
      <div className="pills">
        <span className="pill" title={nf?.last_record ? `Dernier flux ${ago(nf.last_record)}` : "Aucun flux reçu"}>
          <Dot on={nf?.online} />NetFlow : {nf?.online ? "En ligne" : "Hors ligne"}
        </span>
        <span className="pill" title={llm?.error ?? ""}>
          <Dot on={llm?.online} />LLM : {llm?.online ? "En ligne" : llm?.online === null ? "…" : "Hors ligne"}
          <span className="muted">({llm?.cloud ? "cloud" : "local"} · {llm?.model ?? "?"})</span>
        </span>
        <span className="pill tight" title={ise?.last_error ?? ise?.pxgrid?.error ?? ""}>
          <Dot on={ise?.online} />
          <span>Cisco ISE : {ise?.online ? "En ligne" : "Hors ligne"}</span>
          <span className="muted">
            ({ise?.online ? `synchro ${ago(ise.last_sync)} · ${ise.sgacl_count} SGACL · ${ise.cell_count} cellules` : "matrice non synchronisée"})
          </span>
          <button type="button" className="btn pill-btn" onClick={onResync} aria-label="Resynchroniser la matrice TrustSec depuis ISE">
            Resynchroniser
          </button>
        </span>
        <span className="pill" style={{ background: "var(--divider)", color: "var(--text-2)" }}>
          {status?.write_mode === "enforce" ? "Écriture : enforce" : "Écriture : monitor"}
        </span>
        <button type="button" className="btn" onClick={onToggleView} aria-pressed={view === "settings"}>
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
            <path d="M2 4h7M13 4h1M2 12h1M7 12h7M2 8h3M9 8h5" />
            <circle cx="11" cy="4" r="1.8" /><circle cx="5" cy="12" r="1.8" /><circle cx="7" cy="8" r="1.8" />
          </svg>
          {view === "settings" ? "Retour au dashboard" : "Configuration"}
        </button>
        <button type="button" className="btn link" onClick={onLogout}>Déconnexion</button>
      </div>
    </header>
  );
}
