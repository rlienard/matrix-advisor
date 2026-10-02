import { useEffect, useMemo, useState } from "react";
import { ApiError, get, post, put } from "../api";
import type { Config } from "../types";

type Tab = "llm" | "ise" | "collector";
type Kind = "text" | "password" | "number" | "select" | "toggle" | "list";

interface Field {
  path: string;
  label: string;
  kind?: Kind;
  options?: [string, string][];
  required?: boolean;
  mono?: boolean;
  help?: string;
  placeholder?: string;
  disabled?: boolean;
  check?: (v: string) => string;
}

interface Section {
  title: string;
  note?: { text: string; tone: "warn" | "info" };
  action?: "discover";
  fields: (Field | false)[];
}

const getAt = (o: unknown, path: string): unknown =>
  path.split(".").reduce<unknown>((cur, k) => (cur && typeof cur === "object" ? (cur as Record<string, unknown>)[k] : undefined), o);

function setAt<T>(o: T, path: string, value: unknown): T {
  const out = structuredClone(o) as Record<string, unknown>;
  const parts = path.split(".");
  let cur = out;
  for (const p of parts.slice(0, -1)) cur = cur[p] as Record<string, unknown>;
  cur[parts[parts.length - 1]] = value;
  return out as T;
}

const isInt = (lo: number, hi: number) => (v: string) => (/^\d+$/.test(v) && +v >= lo && +v <= hi ? "" : `Entier entre ${lo} et ${hi}`);
const host = (v: string) => (/^[A-Za-z0-9.:-]+$/.test(v) ? "" : "Nom d’hôte ou adresse IP attendu");
const absPath = (v: string) => (v.startsWith("/") ? "" : "Chemin absolu attendu");
const url = (v: string) => (/^https?:\/\/\S+$/.test(v) ? "" : "URL en http:// ou https:// attendue");

const SECRET_MASK = "********";

export default function Settings({ onSaved }: { onSaved: () => void }) {
  const [saved, setSaved] = useState<Config | null>(null);
  const [cfg, setCfg] = useState<Config | null>(null);
  const [tab, setTab] = useState<Tab>("llm");
  const [tests, setTests] = useState<Partial<Record<Tab, { st: "testing" | "ok" | "error"; msg: string }>>>({});
  const [msg, setMsg] = useState("");
  const [showYaml, setShowYaml] = useState(false);
  const [nodes, setNodes] = useState<{ st: "idle" | "loading" | "ok" | "error"; pan: string; list: { fqdn: string; ip: string; roles: string[]; services: string[] }[]; total: number; msg?: string }>({ st: "idle", pan: "", list: [], total: 0 });

  useEffect(() => {
    get<Config>("/config").then((c) => {
      setSaved(c);
      setCfg(c);
    });
  }, []);

  const set = (path: string, value: unknown) => {
    setCfg((c) => (c ? setAt(c, path, value) : c));
    const t = path.split(".")[0] as Tab;
    setTests((x) => ({ ...x, [t]: undefined }));
    setMsg("");
  };

  const discovered = cfg && nodes.st === "ok" && nodes.pan === cfg.ise.pan;

  const sections: Record<Tab, { label: string; title: string; desc: string; sections: Section[] }> | null = useMemo(() => {
    if (!cfg) return null;
    const cloud = cfg.llm.provider === "anthropic" || cfg.llm.provider === "azure";
    return {
      llm: {
        label: "Modèle IA", title: "Connexion au modèle IA",
        desc: "Le modèle juge la plausibilité et rédige la justification. Il ne reçoit que des paires SGT, des ports et des volumes.",
        sections: [
          {
            title: "Fournisseur et modèle",
            note: cloud ? { tone: "warn", text: "Fournisseur cloud : seuls des noms de SGT, des ports et des volumes quittent le réseau, jamais d’adresse IP. Pour un déploiement 100 % on-prem, choisissez Ollama ou vLLM." } : undefined,
            fields: [
              { path: "llm.provider", label: "Fournisseur", kind: "select", options: [["ollama", "Ollama (local)"], ["openai", "vLLM / API compatible OpenAI (local)"], ["anthropic", "Anthropic API (cloud)"], ["azure", "Azure OpenAI (cloud)"]] },
              { path: "llm.endpoint", label: "URL du endpoint", required: true, mono: true, check: url, placeholder: "http://ollama:11434" },
              { path: "llm.model", label: cfg.llm.provider === "azure" ? "Déploiement" : "Modèle", required: true, mono: true },
              cfg.llm.provider !== "ollama" && { path: "llm.api_key", label: "Clé API", kind: "password", required: cfg.llm.provider !== "openai", help: "Stockée côté serveur, jamais renvoyée au navigateur" },
              cfg.llm.provider === "azure" && { path: "llm.api_version", label: "Version d’API Azure", mono: true },
              { path: "llm.temperature", label: "Température", kind: "number", mono: true, check: (v) => (+v >= 0 && +v <= 2 ? "" : "Valeur entre 0 et 2"), help: "Basse = propositions reproductibles" },
              { path: "llm.timeout_s", label: "Timeout (s)", kind: "number", mono: true, check: isInt(1, 600) },
              { path: "llm.language", label: "Langue des justifications", kind: "select", options: [["fr", "Français"], ["en", "English"], ["de", "Deutsch"], ["es", "Español"], ["it", "Italiano"], ["nl", "Nederlands"]] },
            ],
          },
          {
            title: "Déclenchement de l’agent",
            fields: [
              { path: "llm.trigger", label: "Mode", kind: "select", options: [["event", "Événementiel : nouvelle paire SGT détectée"], ["scheduled", "Planifié"]] },
              cfg.llm.trigger === "scheduled" && { path: "llm.scheduled_minutes", label: "Intervalle (min)", kind: "number", mono: true, check: isInt(5, 1440) },
              { path: "llm.learning_days", label: "Phase d’apprentissage (jours)", kind: "number", mono: true, check: isInt(0, 90), help: "Aucune proposition pendant cette période" },
              { path: "llm.send_ip_addresses", label: "Ne jamais envoyer d’adresse IP au modèle", kind: "toggle", disabled: true, help: "Toujours actif : la résolution IP → SGT se fait en amont, et chaque requête est contrôlée avant envoi." },
            ],
          },
        ],
      },
      ise: {
        label: "Cisco ISE", title: "Connexion à Cisco ISE",
        desc: "API ERS/OpenAPI pour lire et écrire la matrice TrustSec, pxGrid pour le contexte des endpoints et les notifications de changement.",
        sections: [
          {
            title: "ERS / OpenAPI · lecture et écriture de la matrice",
            fields: [
              { path: "ise.pan", label: "Nœud PAN (FQDN ou IP)", required: true, mono: true, check: host, placeholder: "ise-pan.example.local" },
              { path: "ise.openapi.username", label: "Utilisateur API", required: true, mono: true, help: "Compte avec le rôle ERS Admin" },
              { path: "ise.openapi.password", label: "Mot de passe", kind: "password", required: true, help: "Stocké côté serveur" },
              { path: "ise.openapi.port", label: "Port HTTPS", kind: "number", mono: true, check: isInt(1, 65535) },
              { path: "ise.openapi.verify_tls", label: "Vérifier le certificat TLS d’ISE", kind: "toggle", help: "À ne désactiver qu’en lab." },
              { path: "ise.openapi.base_url", label: "URL de base (lab / simulateur)", mono: true, help: "Laisser vide en production : https://<PAN>:<port>" },
            ],
          },
          {
            title: "pxGrid · contexte des endpoints et notifications TrustSec",
            action: "discover",
            fields: [
              discovered
                ? { path: "ise.pxgrid.node", label: "Nœud pxGrid", kind: "select", required: true,
                    options: nodes.list.map((n) => [n.fqdn, `${n.fqdn} · ${n.ip} · ${[...n.roles, ...n.services].filter((x) => /admin|monitor|pxgrid|session/i.test(x)).join(" · ")}`] as [string, string]),
                    help: "Seuls les nœuds avec le service pxGrid activé sont proposés" }
                : { path: "ise.pxgrid.node", label: "Nœud pxGrid", mono: true, check: host, help: "Saisie manuelle, ou utilisez la découverte ci-dessus", placeholder: "ise-px1.example.local" },
              { path: "ise.pxgrid.client_name", label: "Nom du client pxGrid", required: true, mono: true, help: "À approuver dans ISE au premier lancement" },
              { path: "ise.pxgrid.auth", label: "Authentification", kind: "select", options: [["certificate", "Certificat client"], ["password", "Mot de passe pxGrid"]] },
              cfg.ise.pxgrid.auth === "certificate" && { path: "ise.pxgrid.client_cert", label: "Certificat client (chemin)", mono: true, check: absPath },
              cfg.ise.pxgrid.auth === "certificate" && { path: "ise.pxgrid.client_key", label: "Clé privée (chemin)", mono: true, check: absPath },
              cfg.ise.pxgrid.auth === "password" && { path: "ise.pxgrid.password", label: "Mot de passe pxGrid", kind: "password", help: "Vide : un compte est créé et doit être approuvé dans ISE" },
              { path: "ise.pxgrid.ca_cert", label: "CA d’ISE (chemin)", mono: true, help: "Optionnel si le magasin système suffit" },
              { path: "ise.pxgrid.subscribe", label: "Abonnement websocket (sinon interrogation périodique)", kind: "toggle" },
              { path: "ise.pxgrid.base_url", label: "URL de base pxGrid (lab / simulateur)", mono: true, help: "Laisser vide en production : https://<nœud>:8910" },
            ],
          },
          {
            title: "Politique d’écriture",
            note: cfg.ise.write_mode === "enforce"
              ? { tone: "warn", text: "Mode enforce : une nouvelle cellule approuvée bloque immédiatement le trafic non autorisé." }
              : { tone: "info", text: "Mode monitor : les nouvelles cellules sont écrites en MONITOR (les refus sont journalisés, rien n’est bloqué). Une cellule existante garde toujours son statut." },
            fields: [
              { path: "ise.write_mode", label: "Mode d’écriture", kind: "select", options: [["monitor", "Monitor (recommandé pour démarrer)"], ["enforce", "Enforce"]] },
              { path: "ise.sgacl_prefix", label: "Préfixe des SGACL créées", required: true, mono: true, check: (v) => (/^[A-Za-z][A-Za-z0-9_]*$/.test(v) ? "" : "Lettres, chiffres et _ uniquement"), help: "Nouveaux contrats et clones portent ce préfixe" },
              { path: "ise.reconcile_minutes", label: "Réconciliation complète (min)", kind: "number", mono: true, check: isInt(1, 1440), help: "Rattrape les notifications pxGrid manquées" },
              { path: "ise.matrix_default", label: "Politique par défaut de la matrice", kind: "select", options: [["deny", "Deny IP (cible)"], ["permit", "Permit IP (avant bascule)"]], help: "Sert à calculer ce qui serait bloqué" },
            ],
          },
        ],
      },
      collector: {
        label: "Collecteur NetFlow", title: "Collecteur NetFlow / IPFIX",
        desc: "GoFlow2 reçoit les flux des switches et écrit du JSON. Le backend l’agrège dans DuckDB par paire SGT et archive les flux bruts en Parquet.",
        sections: [
          {
            title: "Réception (GoFlow2)",
            fields: [
              { path: "collector.input_file", label: "Sortie JSON de GoFlow2", required: true, mono: true, check: absPath, help: "Chemin passé à -transport.file" },
              { path: "collector.listen", label: "Adresse d’écoute", required: true, mono: true, check: host, help: "Informatif : à refléter dans les options de GoFlow2" },
              { path: "collector.ipfix_port", label: "Port IPFIX (UDP)", kind: "number", mono: true, check: isInt(1, 65535) },
              { path: "collector.netflow_v9_port", label: "Port NetFlow v9 (UDP)", kind: "number", mono: true,
                check: (v) => (v === String(cfg.collector.ipfix_port) ? "Doit différer du port IPFIX" : isInt(1, 65535)(v)) },
              { path: "collector.allowed_exporters", label: "Exporteurs autorisés", kind: "list", required: true, mono: true, help: "CIDR séparés par des virgules",
                check: (v) => (v.split(",").every((x) => /^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(x.trim())) ? "" : "Format attendu : 10.10.0.0/16, 10.20.0.0/16") },
            ],
          },
          {
            title: "Stockage et agrégation",
            fields: [
              { path: "collector.duckdb_path", label: "Base DuckDB", required: true, mono: true, check: absPath },
              { path: "collector.parquet_dir", label: "Archive Parquet des flux bruts", required: true, mono: true, check: absPath },
              { path: "collector.rotate_minutes", label: "Écriture d’un fichier Parquet toutes les (min)", kind: "number", mono: true, check: isInt(1, 1440) },
              { path: "collector.retention_days", label: "Rétention (jours)", kind: "number", mono: true, check: isInt(1, 365) },
              { path: "collector.aggregation_seconds", label: "Analyse des nouvelles paires toutes les (s)", kind: "number", mono: true, check: isInt(5, 3600) },
              { path: "collector.stale_after_seconds", label: "Hors ligne après (s) sans flux", kind: "number", mono: true, check: isInt(30, 86400) },
            ],
          },
        ],
      },
    };
  }, [cfg, discovered, nodes.list]);

  if (!cfg || !saved || !sections) return <div className="card">Chargement de la configuration…</div>;

  const valueOf = (f: Field) => {
    const v = getAt(cfg, f.path);
    if (f.kind === "list") return (v as string[]).join(", ");
    return v === undefined || v === null ? "" : String(v);
  };
  const errorOf = (f: Field) => {
    if (f.kind === "toggle" || f.kind === "select") return "";
    const v = valueOf(f).trim();
    if (f.kind === "password" && v === SECRET_MASK) return "";
    if (f.required && !v) return "Champ requis";
    return v && f.check ? f.check(v) : "";
  };
  const fieldsOf = (t: Tab) => sections[t].sections.flatMap((s) => s.fields.filter(Boolean) as Field[]);
  const errCount = (t: Tab) => fieldsOf(t).filter((f) => errorOf(f)).length;
  const totalErr = errCount("llm") + errCount("ise") + errCount("collector");
  const dirty = JSON.stringify(cfg) !== JSON.stringify(saved);
  const test = tests[tab];

  const update = (f: Field, raw: string | boolean) => {
    if (f.kind === "number") set(f.path, raw === "" ? "" : Number(raw));
    else if (f.kind === "list") set(f.path, String(raw).split(",").map((x) => x.trim()).filter(Boolean));
    else set(f.path, raw);
  };

  async function runTest() {
    if (errCount(tab)) return setTests((x) => ({ ...x, [tab]: { st: "error", msg: "Corrigez les champs en erreur avant de tester la connexion." } }));
    setTests((x) => ({ ...x, [tab]: { st: "testing", msg: "Test de connexion en cours…" } }));
    try {
      const r = await post<{ ok: boolean; message: string }>(`/config/test/${tab}`, { config: cfg });
      setTests((x) => ({ ...x, [tab]: { st: r.ok ? "ok" : "error", msg: r.message } }));
    } catch (e) {
      setTests((x) => ({ ...x, [tab]: { st: "error", msg: (e as Error).message } }));
    }
  }

  async function discover() {
    if (!cfg) return;
    if (["ise.pan", "ise.openapi.username", "ise.openapi.password"].some((p) => errorOf({ path: p, label: "", required: true }))) {
      return setNodes({ st: "error", pan: cfg.ise.pan, list: [], total: 0, msg: "Renseignez d’abord le nœud PAN, l’utilisateur et le mot de passe API." });
    }
    setNodes({ st: "loading", pan: cfg.ise.pan, list: [], total: 0 });
    try {
      const r = await post<{ nodes: unknown[]; pxgrid: { fqdn: string; ip: string; roles: string[]; services: string[] }[] }>("/ise/pxgrid-nodes", { config: cfg });
      setNodes({ st: "ok", pan: cfg.ise.pan, list: r.pxgrid, total: r.nodes.length });
      if (r.pxgrid.length && !r.pxgrid.some((n) => n.fqdn === cfg.ise.pxgrid.node)) set("ise.pxgrid.node", r.pxgrid[0].fqdn);
    } catch (e) {
      setNodes({ st: "error", pan: cfg.ise.pan, list: [], total: 0, msg: (e as Error).message });
    }
  }

  async function save() {
    try {
      const r = await put<Config>("/config", { config: cfg });
      setSaved(r);
      setCfg(r);
      setMsg("Configuration enregistrée · les services concernés redémarrent.");
      onSaved();
    } catch (e) {
      const detail = e instanceof ApiError && Array.isArray(e.body.detail)
        ? (e.body.detail as { loc: string[]; msg: string }[]).map((d) => `${d.loc.join(".")} : ${d.msg}`).join(" · ")
        : (e as Error).message;
      setMsg(`Enregistrement refusé : ${detail}`);
    }
  }

  const discState = discovered ? "ok" : nodes.pan === cfg.ise.pan ? nodes.st : "idle";
  const tabs: Tab[] = ["llm", "ise", "collector"];

  return (
    <section className="card settings" aria-label="Configuration des connexions">
      <nav aria-label="Sections de configuration">
        <h2 style={{ marginBottom: 8 }}>Configuration</h2>
        {tabs.map((t) => {
          const st = tests[t];
          const e = errCount(t);
          const color = e ? "var(--danger)" : !st ? "#596069" : st.st === "ok" ? "var(--ok)" : st.st === "testing" ? "var(--pend)" : "var(--danger)";
          return (
            <button key={t} type="button" className="tab" aria-current={t === tab ? "page" : undefined} onClick={() => setTab(t)}>
              <span style={{ flexGrow: 1, display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>{sections[t].label}</span>
                <span className="small muted">
                  {e ? `${e} champ${e > 1 ? "s" : ""} à corriger` : !st ? "Connexion non testée" : st.st === "ok" ? "Connexion testée" : st.st === "testing" ? "Test en cours…" : "Échec du test"}
                </span>
              </span>
              <span className="sdot" style={{ background: color }} />
            </button>
          );
        })}
        <p className="small muted" style={{ margin: "12px 0 0" }}>
          Les secrets (mots de passe, clés API) sont stockés côté serveur (fichier secrets.json en 0600, ou variables d’environnement) et ne sont jamais renvoyés au navigateur.
        </p>
      </nav>

      <div className="body">
        <div>
          <h3 style={{ fontSize: 18, fontWeight: 700 }}>{sections[tab].title}</h3>
          <p className="muted" style={{ margin: "4px 0 0", fontSize: 13 }}>{sections[tab].desc}</p>
        </div>

        {sections[tab].sections.map((sec) => (
          <fieldset key={sec.title}>
            <legend>{sec.title}</legend>
            {sec.note && <div className={`note ${sec.note.tone}`}>{sec.note.text}</div>}
            {sec.action === "discover" && (
              <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 10 }}>
                <button type="button" className="btn outline" onClick={discover} disabled={discState === "loading"}>
                  <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"><circle cx="7" cy="7" r="4.5" /><path d="M10.5 10.5L14 14" /></svg>
                  {discState === "loading" ? "Découverte en cours…" : discState === "ok" ? "Relancer la découverte" : "Découvrir les nœuds pxGrid"}
                </button>
                <span role="status" className="small" style={{ color: discState === "ok" ? "var(--ok-fg)" : discState === "error" ? "var(--bad-fg)" : "var(--text-3)" }}>
                  {discState === "ok" ? `${nodes.total} nœuds dans le déploiement, dont ${nodes.list.length} avec le service pxGrid activé.`
                    : discState === "error" ? nodes.msg
                    : discState === "loading" ? `Interrogation de l’API de déploiement sur ${cfg.ise.pan}…`
                    : "Interroge l’API de déploiement ISE pour lister les nœuds où le service pxGrid est activé."}
                </span>
              </div>
            )}
            <div className="grid-fields">
              {(sec.fields.filter(Boolean) as Field[]).map((f) => {
                const id = "cfg-" + f.path.replace(/\./g, "-");
                const err = errorOf(f);
                const help = err || f.help || "";
                if (f.kind === "toggle") {
                  return (
                    <div key={f.path} className="field full">
                      <label className="check" htmlFor={id}>
                        <input id={id} type="checkbox" disabled={f.disabled}
                          checked={f.path === "llm.send_ip_addresses" ? true : !!getAt(cfg, f.path)}
                          onChange={(e) => !f.disabled && update(f, e.target.checked)} />
                        <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                          <span style={{ fontSize: 13, fontWeight: 600 }}>{f.label}</span>
                          {f.help && <span className="help">{f.help}</span>}
                        </span>
                      </label>
                    </div>
                  );
                }
                return (
                  <div key={f.path} className="field">
                    <label className="field-label" htmlFor={id}>{f.label}{f.required ? " *" : ""}</label>
                    {f.kind === "select" ? (
                      <select id={id} className="input" value={valueOf(f)} onChange={(e) => update(f, e.target.value)} aria-describedby={id + "-help"}>
                        {f.options!.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                      </select>
                    ) : (
                      <input id={id} className={`input ${f.mono ? "mono" : ""} ${err ? "invalid" : ""}`}
                        type={f.kind === "password" ? "password" : "text"} inputMode={f.kind === "number" ? "decimal" : undefined}
                        value={valueOf(f)} placeholder={f.placeholder} autoComplete="off" spellCheck={false}
                        aria-invalid={!!err} aria-describedby={id + "-help"}
                        onFocus={(e) => f.kind === "password" && e.target.value === SECRET_MASK && update(f, "")}
                        onChange={(e) => update(f, e.target.value)} />
                    )}
                    {help && <span id={id + "-help"} className={`help ${err ? "err" : ""}`}>{help}</span>}
                  </div>
                );
              })}
            </div>
          </fieldset>
        ))}

        {test && <div role="status" className={`note ${test.st === "ok" ? "ok" : test.st === "error" ? "err" : "info"}`} style={{ fontSize: 13 }}>{test.msg}</div>}
        {showYaml && (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span className="section-label">config.yaml généré · toutes les sections</span>
            <pre className="code" style={{ overflowX: "auto" }}>{toYaml(cfg)}</pre>
          </div>
        )}

        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, paddingTop: 16, borderTop: "1px solid var(--divider)" }}>
          <button type="button" className="btn outline" onClick={runTest} disabled={test?.st === "testing"}>
            {test?.st === "testing" ? "Test en cours…" : "Tester la connexion"}
          </button>
          <button type="button" className="btn" aria-pressed={showYaml} onClick={() => setShowYaml(!showYaml)}>
            {showYaml ? "Masquer config.yaml" : "Voir config.yaml"}
          </button>
          <span style={{ flexGrow: 1 }} />
          <span role="status" className="small" style={{ color: totalErr ? "var(--bad-fg)" : dirty ? "var(--warn-fg)" : "var(--text-3)" }}>
            {msg || (totalErr ? "Corrigez les champs en erreur pour enregistrer" : dirty ? "Modifications non enregistrées" : "Configuration à jour")}
          </span>
          {dirty && <button type="button" className="btn link" onClick={() => { setCfg(saved); setTests({}); setMsg(""); }}>Annuler les changements</button>}
          <button type="button" className="btn ok" disabled={!dirty || totalErr > 0} onClick={save}>Enregistrer</button>
        </div>
      </div>
    </section>
  );
}

const ENV: Record<string, string> = {
  "llm.api_key": "MA_LLM_API_KEY",
  "ise.openapi.password": "MA_ISE_PASSWORD",
  "ise.pxgrid.password": "MA_PXGRID_PASSWORD",
};

function toYaml(cfg: Config): string {
  const lines = ["# config.yaml · Matrix Advisor", "# Les secrets sont lus depuis des variables d’environnement ou secrets.json."];
  const walk = (obj: Record<string, unknown>, prefix: string, indent: string) => {
    for (const [k, v] of Object.entries(obj)) {
      const path = prefix ? `${prefix}.${k}` : k;
      if (k.endsWith("_from_env") || path.startsWith("server")) continue;
      if (ENV[path]) lines.push(`${indent}${k}: \${${ENV[path]}}`);
      else if (Array.isArray(v)) lines.push(`${indent}${k}: [${v.join(", ")}]`);
      else if (v && typeof v === "object") {
        if (!Object.keys(v).length) lines.push(`${indent}${k}: {}`);
        else {
          lines.push(`${indent}${k}:`);
          walk(v as Record<string, unknown>, path, indent + "  ");
        }
      } else lines.push(`${indent}${k}: ${v === "" ? '""' : String(v)}`);
    }
  };
  walk(cfg as unknown as Record<string, unknown>, "", "");
  return lines.join("\n");
}
