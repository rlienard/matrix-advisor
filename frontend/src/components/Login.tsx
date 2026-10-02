import { useState } from "react";
import { ApiError, post } from "../api";
import { LangSwitch, useI18n } from "../i18n";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const { m } = useI18n();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await post("/auth/login", { password });
      onLogin();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : m.login.failed);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card login" onSubmit={submit}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
        <div className="brand">
          <h1>Matrix Advisor</h1>
          <p>SD-Access · Default-Deny</p>
        </div>
        <LangSwitch />
      </div>
      <div className="field">
        <label className="field-label" htmlFor="pw">{m.login.password}</label>
        <input id="pw" className="input" type="password" autoComplete="current-password" autoFocus
          value={password} onChange={(e) => setPassword(e.target.value)} />
        <span className="help">{m.login.help}</span>
      </div>
      {error && <div className="note err" role="alert">{error}</div>}
      <button className="btn primary" type="submit" disabled={busy || !password}>{m.login.submit}</button>
    </form>
  );
}
