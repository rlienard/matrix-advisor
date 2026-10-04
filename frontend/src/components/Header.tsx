import type { Status } from "../types";
import { useI18n } from "../i18n";

export type Service = "collector" | "ise" | "llm";

interface Props {
  status: Status | null;
  view: "dash" | "settings";
  onToggleView: () => void;
  onOpenSettings: (tab?: Service) => void;
  onLogout: () => void;
}

// Services that are down, in the order of the settings menu. The LLM is only down once a call
// (health check or real use) got no answer: "unknown yet" (null) is not an outage.
export function servicesDown(status: Status | null): Service[] {
  if (!status) return [];
  const down: Service[] = [];
  if (!status.netflow.online) down.push("collector");
  if (!status.ise.online) down.push("ise");
  if (status.llm.online === false) down.push("llm");
  return down;
}

export default function Header({ status, view, onToggleView, onOpenSettings, onLogout }: Props) {
  const { m } = useI18n();
  const h = m.header;
  const names: Record<Service, string> = { collector: "NetFlow", ise: "Cisco ISE", llm: m.settings.llm.label };
  const down = servicesDown(status);
  const label = !status ? "…" : down.length ? h.svcDown(down.map((s) => names[s]).join(", ")) : h.online;
  return (
    <header className="header">
      <div className="brand">
        <h1>Matrix Advisor</h1>
        <span className="tag">SD-Access · Default-Deny</span>
        <p>{h.subtitle}</p>
      </div>
      <div className="pills">
        <button type="button" className="pill pill-status" title={h.statusTitle} onClick={() => onOpenSettings(down[0])}>
          <span className={`dot ${!status ? "" : down.length ? "off" : "on"}`} />
          {h.services}{label}
        </button>
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
