import { useEffect, useMemo, useState } from "react";
import { ApiError, get, post, put } from "../api";
import { useI18n } from "../i18n";
import { MESSAGES, type Messages } from "../messages";
import type { Config } from "../types";

type Tab = "llm" | "ise" | "collector" | "lang";
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

function checks(s: Messages["settings"]) {
  return {
    isInt: (lo: number, hi: number) => (v: string) => (/^\d+$/.test(v) && +v >= lo && +v <= hi ? "" : s.intBetween(lo, hi)),
    host: (v: string) => (/^[A-Za-z0-9.:-]+$/.test(v) ? "" : s.hostExpected),
    absPath: (v: string) => (v.startsWith("/") ? "" : s.absPathExpected),
    url: (v: string) => (/^https?:\/\/\S+$/.test(v) ? "" : s.urlExpected),
  };
}

const SECRET_MASK = "********";

export default function Settings({ onSaved }: { onSaved: () => void }) {
  const [saved, setSaved] = useState<Config | null>(null);
  const [cfg, setCfg] = useState<Config | null>(null);
  const [tab, setTab] = useState<Tab>("llm");
  const [tests, setTests] = useState<Partial<Record<Tab, { st: "testing" | "ok" | "error"; msg: string }>>>({});
  const [msg, setMsg] = useState("");
  const [showYaml, setShowYaml] = useState(false);
  const { m, setLang } = useI18n();
  const s = m.settings;
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
    const { isInt, host, absPath, url } = checks(s);
    const L = s.llm, I = s.ise, C = s.collector, G = s.lang;
    return {
      llm: {
        label: L.label, title: L.title, desc: L.desc,
        sections: [
          {
            title: L.provider,
            note: cloud ? { tone: "warn", text: L.cloudNote } : undefined,
            fields: [
              { path: "llm.provider", label: L.providerLabel, kind: "select", options: Object.entries(L.providers) },
              { path: "llm.endpoint", label: L.endpoint, required: true, mono: true, check: url, placeholder: "http://ollama:11434" },
              { path: "llm.model", label: cfg.llm.provider === "azure" ? L.deployment : L.model, required: true, mono: true },
              cfg.llm.provider !== "ollama" && { path: "llm.api_key", label: L.apiKey, kind: "password", required: cfg.llm.provider !== "openai", help: L.apiKeyHelp },
              cfg.llm.provider === "azure" && { path: "llm.api_version", label: L.apiVersion, mono: true },
              { path: "llm.temperature", label: L.temperature, kind: "number", mono: true, check: (v) => (+v >= 0 && +v <= 2 ? "" : L.temperatureCheck), help: L.temperatureHelp },
              { path: "llm.timeout_s", label: L.timeout, kind: "number", mono: true, check: isInt(1, 600) },
            ],
          },
          {
            title: L.trigger,
            fields: [
              { path: "llm.trigger", label: L.mode, kind: "select", options: Object.entries(L.triggers) },
              cfg.llm.trigger === "scheduled" && { path: "llm.scheduled_minutes", label: L.interval, kind: "number", mono: true, check: isInt(5, 1440) },
              { path: "llm.learning_days", label: L.learning, kind: "number", mono: true, check: isInt(0, 90), help: L.learningHelp },
              { path: "llm.send_ip_addresses", label: L.noIp, kind: "toggle", disabled: true, help: L.noIpHelp },
            ],
          },
        ],
      },
      ise: {
        label: I.label, title: I.title, desc: I.desc,
        sections: [
          {
            title: I.openapi,
            fields: [
              { path: "ise.pan", label: I.pan, required: true, mono: true, check: host, placeholder: "ise-pan.example.local" },
              { path: "ise.openapi.username", label: I.user, required: true, mono: true, help: I.userHelp },
              { path: "ise.openapi.password", label: I.password, kind: "password", required: true, help: I.passwordHelp },
              { path: "ise.openapi.port", label: I.port, kind: "number", mono: true, check: isInt(1, 65535) },
              { path: "ise.openapi.verify_tls", label: I.verifyTls, kind: "toggle", help: I.verifyTlsHelp },
              { path: "ise.openapi.base_url", label: I.baseUrl, mono: true, help: I.baseUrlHelp },
            ],
          },
          {
            title: I.pxgrid,
            action: "discover",
            fields: [
              discovered
                ? { path: "ise.pxgrid.node", label: I.node, kind: "select", required: true,
                    options: nodes.list.map((n) => [n.fqdn, `${n.fqdn} · ${n.ip} · ${[...n.roles, ...n.services].filter((x) => /admin|monitor|pxgrid|session/i.test(x)).join(" · ")}`] as [string, string]),
                    help: I.nodeDiscoveredHelp }
                : { path: "ise.pxgrid.node", label: I.node, mono: true, check: host, help: I.nodeManualHelp, placeholder: "ise-px1.example.local" },
              { path: "ise.pxgrid.client_name", label: I.clientName, required: true, mono: true, help: I.clientNameHelp },
              { path: "ise.pxgrid.auth", label: I.auth, kind: "select", options: Object.entries(I.auths) },
              cfg.ise.pxgrid.auth === "certificate" && { path: "ise.pxgrid.client_cert", label: I.clientCert, mono: true, check: absPath },
              cfg.ise.pxgrid.auth === "certificate" && { path: "ise.pxgrid.client_key", label: I.clientKey, mono: true, check: absPath },
              cfg.ise.pxgrid.auth === "password" && { path: "ise.pxgrid.password", label: I.pxPassword, kind: "password", help: I.pxPasswordHelp },
              { path: "ise.pxgrid.ca_cert", label: I.caCert, mono: true, help: I.caCertHelp },
              { path: "ise.pxgrid.subscribe", label: I.subscribe, kind: "toggle" },
              { path: "ise.pxgrid.base_url", label: I.pxBaseUrl, mono: true, help: I.pxBaseUrlHelp },
            ],
          },
          {
            title: I.writePolicy,
            note: cfg.ise.write_mode === "enforce"
              ? { tone: "warn", text: I.enforceNote }
              : { tone: "info", text: I.monitorNote },
            fields: [
              { path: "ise.write_mode", label: I.writeMode, kind: "select", options: Object.entries(I.writeModes) },
              { path: "ise.sgacl_prefix", label: I.prefix, required: true, mono: true, check: (v) => (/^[A-Za-z][A-Za-z0-9_]*$/.test(v) ? "" : I.prefixCheck), help: I.prefixHelp },
              { path: "ise.reconcile_minutes", label: I.reconcile, kind: "number", mono: true, check: isInt(1, 1440), help: I.reconcileHelp },
              { path: "ise.matrix_default", label: I.matrixDefault, kind: "select", options: Object.entries(I.matrixDefaults), help: I.matrixDefaultHelp },
            ],
          },
        ],
      },
      lang: {
        label: G.label, title: G.title, desc: G.desc,
        sections: [
          {
            title: G.interface,
            fields: [
              { path: "ui.language", label: G.uiLanguage, help: G.uiLanguageHelp, kind: "select",
                options: [["fr", MESSAGES.fr.langName], ["en", MESSAGES.en.langName]] },
            ],
          },
        ],
      },
      collector: {
        label: C.label, title: C.title, desc: C.desc,
        sections: [
          {
            title: C.reception,
            fields: [
              { path: "collector.input_file", label: C.inputFile, required: true, mono: true, check: absPath, help: C.inputFileHelp },
              { path: "collector.listen", label: C.listen, required: true, mono: true, check: host, help: C.listenHelp },
              { path: "collector.ipfix_port", label: C.ipfixPort, kind: "number", mono: true, check: isInt(1, 65535) },
              { path: "collector.netflow_v9_port", label: C.v9Port, kind: "number", mono: true,
                check: (v) => (v === String(cfg.collector.ipfix_port) ? C.v9PortCheck : isInt(1, 65535)(v)) },
              { path: "collector.allowed_exporters", label: C.exporters, kind: "list", required: true, mono: true, help: C.exportersHelp,
                check: (v) => (v.split(",").every((x) => /^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(x.trim())) ? "" : C.exportersCheck) },
              { path: "collector.sgt_source", label: C.sgtSource, kind: "select", options: Object.entries(C.sgtSources), help: C.sgtSourceHelp },
            ],
          },
          {
            title: C.storage,
            fields: [
              { path: "collector.duckdb_path", label: C.duckdb, required: true, mono: true, check: absPath },
              { path: "collector.parquet_dir", label: C.parquet, required: true, mono: true, check: absPath },
              { path: "collector.rotate_minutes", label: C.rotate, kind: "number", mono: true, check: isInt(1, 1440) },
              { path: "collector.retention_days", label: C.retention, kind: "number", mono: true, check: isInt(1, 365) },
              { path: "collector.aggregation_seconds", label: C.aggregation, kind: "number", mono: true, check: isInt(5, 3600) },
              { path: "collector.stale_after_seconds", label: C.stale, kind: "number", mono: true, check: isInt(30, 86400) },
            ],
          },
        ],
      },
    };
  }, [cfg, discovered, nodes.list, s]);

  if (!cfg || !saved || !sections) return <div className="card">{s.loading}</div>;

  const valueOf = (f: Field) => {
    const v = getAt(cfg, f.path);
    if (f.kind === "list") return (v as string[]).join(", ");
    return v === undefined || v === null ? "" : String(v);
  };
  const errorOf = (f: Field) => {
    if (f.kind === "toggle" || f.kind === "select") return "";
    const v = valueOf(f).trim();
    if (f.kind === "password" && v === SECRET_MASK) return "";
    if (f.required && !v) return s.required;
    return v && f.check ? f.check(v) : "";
  };
  const fieldsOf = (t: Tab) => sections[t].sections.flatMap((s) => s.fields.filter(Boolean) as Field[]);
  const errCount = (t: Tab) => fieldsOf(t).filter((f) => errorOf(f)).length;
  const totalErr = errCount("llm") + errCount("ise") + errCount("collector") + errCount("lang");
  const dirty = JSON.stringify(cfg) !== JSON.stringify(saved);
  const test = tests[tab];

  const update = (f: Field, raw: string | boolean) => {
    if (f.kind === "number") set(f.path, raw === "" ? "" : Number(raw));
    else if (f.kind === "list") set(f.path, String(raw).split(",").map((x) => x.trim()).filter(Boolean));
    else set(f.path, raw);
  };

  async function runTest() {
    if (errCount(tab)) return setTests((x) => ({ ...x, [tab]: { st: "error", msg: s.fixBeforeTest } }));
    setTests((x) => ({ ...x, [tab]: { st: "testing", msg: s.testRunning } }));
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
      return setNodes({ st: "error", pan: cfg.ise.pan, list: [], total: 0, msg: s.discoverNeedsCreds });
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
      setLang(r.ui.language);
      setMsg(MESSAGES[r.ui.language].settings.saved); // the new language, not the one of this render
      onSaved();
    } catch (e) {
      const detail = e instanceof ApiError && Array.isArray(e.body.detail)
        ? (e.body.detail as { loc: string[]; msg: string }[]).map((d) => `${d.loc.join(".")} : ${d.msg}`).join(" · ")
        : (e as Error).message;
      setMsg(s.saveRefused(detail));
    }
  }

  const discState = discovered ? "ok" : nodes.pan === cfg.ise.pan ? nodes.st : "idle";
  const tabs: Tab[] = ["llm", "ise", "collector", "lang"];

  return (
    <section className="card settings" aria-label={s.aria}>
      <nav aria-label={s.navAria}>
        <h2 style={{ marginBottom: 8 }}>{s.title}</h2>
        {tabs.map((t) => {
          const st = tests[t];
          const e = errCount(t);
          const color = e ? "var(--danger)" : t === "lang" || !st ? "#596069" : st.st === "ok" ? "var(--ok)" : st.st === "testing" ? "var(--pend)" : "var(--danger)";
          return (
            <button key={t} type="button" className="tab" aria-current={t === tab ? "page" : undefined} onClick={() => setTab(t)}>
              <span style={{ flexGrow: 1, display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>{sections[t].label}</span>
                <span className="small muted">
                  {e ? s.toFix(e) : t === "lang" ? MESSAGES[cfg.ui.language].langName : !st ? s.untested : st.st === "ok" ? s.tested : st.st === "testing" ? s.testing : s.testFailed}
                </span>
              </span>
              <span className="sdot" style={{ background: color }} />
            </button>
          );
        })}
        <p className="small muted" style={{ margin: "12px 0 0" }}>
          {s.secretsNote}
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
                  {discState === "loading" ? s.discovering : discState === "ok" ? s.rediscover : s.discover}
                </button>
                <span role="status" className="small" style={{ color: discState === "ok" ? "var(--ok-fg)" : discState === "error" ? "var(--bad-fg)" : "var(--text-3)" }}>
                  {discState === "ok" ? s.discovered(nodes.total, nodes.list.length)
                    : discState === "error" ? nodes.msg
                    : discState === "loading" ? s.discoveringOn(cfg.ise.pan)
                    : s.discoverHelp}
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
            <span className="section-label">{s.yamlTitle}</span>
            <pre className="code" style={{ overflowX: "auto" }}>{toYaml(cfg, s.yamlSecrets)}</pre>
          </div>
        )}

        <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, paddingTop: 16, borderTop: "1px solid var(--divider)" }}>
          {tab !== "lang" && (
            <button type="button" className="btn outline" onClick={runTest} disabled={test?.st === "testing"}>
              {test?.st === "testing" ? s.testing : s.test}
            </button>
          )}
          <button type="button" className="btn" aria-pressed={showYaml} onClick={() => setShowYaml(!showYaml)}>
            {showYaml ? s.hideYaml : s.showYaml}
          </button>
          <span style={{ flexGrow: 1 }} />
          <span role="status" className="small" style={{ color: totalErr ? "var(--bad-fg)" : dirty ? "var(--warn-fg)" : "var(--text-3)" }}>
            {msg || (totalErr ? s.fixToSave : dirty ? s.unsaved : s.upToDate)}
          </span>
          {dirty && <button type="button" className="btn link" onClick={() => { setCfg(saved); setTests({}); setMsg(""); }}>{s.discard}</button>}
          <button type="button" className="btn ok" disabled={!dirty || totalErr > 0} onClick={save}>{s.save}</button>
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

function toYaml(cfg: Config, secretsComment: string): string {
  const lines = ["# config.yaml · Matrix Advisor", secretsComment];
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
