import { useCallback, useEffect, useState } from "react";
import { get, post, setUnauthorizedHandler } from "./api";
import Dashboard from "./components/Dashboard";
import Header from "./components/Header";
import Login from "./components/Login";
import Settings from "./components/Settings";
import { useI18n } from "./i18n";
import type { Status } from "./types";

export default function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined);
  const [view, setView] = useState<"dash" | "settings">("dash");
  const [status, setStatus] = useState<Status | null>(null);
  const { lang } = useI18n();

  useEffect(() => {
    setUnauthorizedHandler(() => setUser(null));
    get<{ user: string | null }>("/auth/me").then((r) => setUser(r.user)).catch(() => setUser(null));
  }, []);

  const refreshStatus = useCallback(() => {
    get<Status>("/status").then(setStatus).catch(() => undefined);
  }, [lang]); // error messages in the status come back in the UI language

  useEffect(() => {
    if (!user) return;
    refreshStatus();
    const t = setInterval(refreshStatus, 15000);
    return () => clearInterval(t);
  }, [user, refreshStatus]);

  if (user === undefined) return null;
  if (!user) return <Login onLogin={() => setUser("admin")} />;

  return (
    <div className="shell">
      <Header
        status={status}
        view={view}
        onToggleView={() => setView(view === "dash" ? "settings" : "dash")}
        onResync={async () => {
          await post("/ise/sync").catch(() => undefined);
          refreshStatus();
        }}
        onLogout={async () => {
          await post("/auth/logout");
          setUser(null);
        }}
      />
      {view === "dash" ? (
        <Dashboard status={status} />
      ) : (
        <Settings onSaved={refreshStatus} />
      )}
    </div>
  );
}
