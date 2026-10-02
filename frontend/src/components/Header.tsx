import type { Status } from "../types";
import { useI18n } from "../i18n";

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
  const { m, ago } = useI18n();
  const h = m.header;
  return (
    <header className="header">
      <div className="brand">
        <h1>Matrix Advisor</h1>
        <span className="tag">SD-Access · Default-Deny</span>
        <p>{h.subtitle}</p>
      </div>
      <div className="pills">
        <span className="pill" title={nf?.last_record ? h.lastFlow(ago(nf.last_record)) : h.noFlow}>
          <Dot on={nf?.online} />{h.label("NetFlow")}{nf?.online ? h.online : h.offline}
        </span>
        <span className="pill" title={llm?.error ?? ""}>
          <Dot on={llm?.online} />{h.label("LLM")}{llm?.online ? h.online : llm?.online === null ? "…" : h.offline}
          <span className="muted">({llm?.cloud ? "cloud" : "local"} · {llm?.model ?? "?"})</span>
        </span>
        <span className="pill tight" title={ise?.last_error ?? ise?.pxgrid?.error ?? ""}>
          <Dot on={ise?.online} />
          <span>{h.label("Cisco ISE")}{ise?.online ? h.online : h.offline}</span>
          <span className="muted">
            ({ise?.online ? h.synced(ago(ise.last_sync), ise.sgacl_count, ise.cell_count) : h.notSynced})
          </span>
          <button type="button" className="btn pill-btn" onClick={onResync} aria-label={h.resyncAria}>
            {h.resync}
          </button>
        </span>
        <span className="pill" style={{ background: "var(--divider)", color: "var(--text-2)" }}>
          {h.writeMode(status?.write_mode === "enforce" ? "enforce" : "monitor")}
        </span>
        <button type="button" className="btn" onClick={onToggleView} aria-pressed={view === "settings"}>
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
            <path d="M2 4h7M13 4h1M2 12h1M7 12h7M2 8h3M9 8h5" />
            <circle cx="11" cy="4" r="1.8" /><circle cx="5" cy="12" r="1.8" /><circle cx="7" cy="8" r="1.8" />
          </svg>
          {view === "settings" ? h.backToDashboard : h.settings}
        </button>
        <button type="button" className="btn link" onClick={onLogout}>{h.logout}</button>
      </div>
    </header>
  );
}
