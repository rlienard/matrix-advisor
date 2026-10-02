import { useState } from "react";
import { ApiError, post } from "../api";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await post("/auth/login", { password });
      onLogin();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Connexion impossible.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="card login" onSubmit={submit}>
      <div className="brand">
        <h1>Matrix Advisor</h1>
        <p>SD-Access · Default-Deny</p>
      </div>
      <div className="field">
        <label className="field-label" htmlFor="pw">Mot de passe administrateur</label>
        <input id="pw" className="input" type="password" autoComplete="current-password" autoFocus
          value={password} onChange={(e) => setPassword(e.target.value)} />
        <span className="help">Au premier démarrage, il est généré dans le fichier initial-admin-password du dossier de données.</span>
      </div>
      {error && <div className="note err" role="alert">{error}</div>}
      <button className="btn primary" type="submit" disabled={busy || !password}>Se connecter</button>
    </form>
  );
}
