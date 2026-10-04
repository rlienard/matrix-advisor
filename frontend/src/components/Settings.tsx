import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, get, post, put } from "../api";
import { useI18n } from "../i18n";
import { MESSAGES, type Messages } from "../messages";
import type { CertInfo, Config, IseNode, LlmModel, Status, TrustImport } from "../types";
import type { Service } from "./Header";

type Tab = "llm" | "ise" | "collector" | "lang";
type Sub = "cluster" | "pxgrid" | "advanced";
// Each settings page (a menu, or an ISE sub-tab) has its own status bar and test button.
type Page = "llm" | "ise:cluster" | "ise:pxgrid" | "ise:advanced" | "collector" | "lang";
type Svc = "llm" | "ise" | "pxgrid" | "collector";
type Kind = "text" | "password" | "number" | "select" | "toggle" | "list" | "file";
type UploadKind = "ca" | "client_cert" | "client_key";
type Tone = "ok" | "error" | "warn" | "info" | "muted";

const PAGE_SVC: Partial<Record<Page, Svc>> = { llm: "llm", "ise:cluster": "ise", "ise:pxgrid": "pxgrid", collector: "collector" };
const SECRET_MASK = "********";

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
  maxWidth?: number;
  onOpen?: () => void;
  upload?: { kind: UploadKind; accept: string; info?: CertInfo | null };
}

interface Section {
  sub?: Sub;
  title?: string;
  note?: { text: string; tone: "warn" | "info" | "err" };
  action?: ReactNode;
  fields: (Field | false | null | undefined)[];
}

type PageEvent =
  | { kind: "test" }
  | { kind: "save"; st: "saving" | "testing" | "ok" | "ko" | "done" | "refused"; svc?: Svc; msg?: string }
  | { kind: "sync"; st: "syncing" | "ok" | "error"; msg?: string };

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

const keep = (xs: (Section | false)[]) => xs.filter(Boolean) as Section[];
const localProvider = (p: Config["llm"]["provider"]) => p === "ollama" || p === "openai";
const cloudProvider = (p: Config["llm"]["provider"]) => p === "anthropic" || p === "azure";
const shortFp = (fp: string) => {
  const b = fp.split(":");
  return b.length > 6 ? `${b.slice(0, 4).join(":")}:…:${b.slice(-2).join(":")}` : fp;
};
const sizeOf = (bytes: number, locale: string) =>
  bytes ? `${(bytes / 1e9).toLocaleString(locale, { maximumFractionDigits: 1 })} ${locale.startsWith("fr") ? "Go" : "GB"}` : "";

async function toBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

interface Props {
  status: Status | null;
  initialTab?: Service;
  onChanged: () => void;
}

export default function Settings({ status, initialTab, onChanged }: Props) {
  const { m, lang, setLang, ago } = useI18n();
  const day = (iso: string) => new Date(iso + (iso.endsWith("Z") ? "" : "Z")).toLocaleDateString(m.locale);
  const s = m.settings;
  const [saved, setSaved] = useState<Config | null>(null);
  const [cfg, setCfg] = useState<Config | null>(null);
  const [tab, setTab] = useState<Tab>(initialTab ?? "llm");
  const [sub, setSub] = useState<Sub>("cluster");
  const [tests, setTests] = useState<Partial<Record<Svc, { st: "testing" | "ok" | "error"; msg: string }>>>({});
  const [events, setEvents] = useState<Partial<Record<Page, PageEvent>>>({});
  const [nodes, setNodes] = useState<{ st: "idle" | "loading" | "ok" | "error"; pan: string; list: IseNode[]; total: number; msg?: string }>(
    { st: "idle", pan: "", list: [], total: 0 });
  const [models, setModels] = useState<{ st: "idle" | "loading" | "ok" | "error"; key: string; list: LlmModel[]; msg?: string }>(
    { st: "idle", key: "", list: [] });
  const [files, setFiles] = useState<Record<string, { name: string; kind: UploadKind; file: File }>>({});
  const [certs, setCerts] = useState<{ ca: CertInfo | null; client: CertInfo | null; trust_import: (TrustImport & { sha256?: string }) | null }>(
    { ca: null, client: null, trust_import: null });
  const [gen, setGen] = useState<{ busy: boolean; info?: CertInfo; trust?: TrustImport; error?: string }>({ busy: false });
  const scanned = useRef(false);

  const page: Page = tab === "ise" ? (`ise:${sub}` as Page) : tab;
  const setEvent = useCallback((p: Page, ev: PageEvent | null) =>
    setEvents((x) => {
      const out = { ...x };
      if (ev) out[p] = ev;
      else delete out[p];
      return out;
    }), []);

  const loadCerts = useCallback(() => {
    get<typeof certs>("/ise/certificates").then(setCerts).catch(() => undefined);
  }, []);

  useEffect(() => {
    get<Config>("/config").then((c) => {
      setSaved(c);
      setCfg(c);
    });
    loadCerts();
  }, [loadCerts]);

  // ---- ISE cluster scan (GET /api/v1/deployment/node through the backend): on load and on save
  const scan = useCallback(async (conf: Config, fillNode: boolean) => {
    const pan = conf.ise.pan.trim();
    if (!pan || !conf.ise.openapi.username.trim() || !conf.ise.openapi.password) {
      setNodes({ st: "error", pan, list: [], total: 0, msg: s.discoverNeedsCreds });
      return;
    }
    setNodes({ st: "loading", pan, list: [], total: 0 });
    try {
      const r = await post<{ nodes: IseNode[]; pxgrid: IseNode[] }>("/ise/pxgrid-nodes", { config: conf });
      setNodes({ st: "ok", pan, list: r.pxgrid, total: r.nodes.length });
      if (fillNode && r.pxgrid.length) {
        setCfg((c) => {
          if (!c) return c;
          let next = c;
          if (!r.pxgrid.some((n) => n.fqdn === c.ise.pxgrid.node)) next = setAt(next, "ise.pxgrid.node", r.pxgrid[0].fqdn);
          const second = next.ise.pxgrid.secondary_node;
          if (second && (second === next.ise.pxgrid.node || !r.pxgrid.some((n) => n.fqdn === second))) {
            next = setAt(next, "ise.pxgrid.secondary_node", "");
          }
          return next;
        });
      }
    } catch (e) {
      setNodes({ st: "error", pan, list: [], total: 0, msg: (e as Error).message });
    }
  }, [s.discoverNeedsCreds]);

  useEffect(() => {
    if (saved && !scanned.current && saved.ise.pan) {
      scanned.current = true;
      scan(saved, !saved.ise.pxgrid.node);
    }
  }, [saved, scan]);

  // ---- model discovery (Ollama GET /api/tags + /api/ps, vLLM GET /v1/models), refreshed on every opening
  const llmUrl = cfg ? (localProvider(cfg.llm.provider) && cfg.llm.location === "local"
    ? `http://localhost:${cfg.llm.port}` : cfg.llm.endpoint) : "";
  const modelKey = cfg ? [cfg.llm.provider, cfg.llm.location, cfg.llm.port, cfg.llm.endpoint].join("|") : "";
  const discoverModels = useCallback(async () => {
    if (!cfg || !localProvider(cfg.llm.provider)) return;
    const { url, isInt } = checks(s);
    const bad = cfg.llm.location === "local" ? isInt(1, 65535)(String(cfg.llm.port)) : url(cfg.llm.endpoint.trim());
    if (bad) return setModels({ st: "error", key: modelKey, list: [], msg: s.mdBadUrl });
    setModels((x) => ({ st: "loading", key: modelKey, list: x.key === modelKey ? x.list : [] }));
    try {
      const r = await post<{ models: LlmModel[] }>("/llm/models", { config: cfg });
      setModels({ st: "ok", key: modelKey, list: r.models });
    } catch (e) {
      setModels({ st: "error", key: modelKey, list: [], msg: s.mdError((e as Error).message) });
    }
  }, [cfg, modelKey, s]);

  useEffect(() => {
    if (tab === "llm" && cfg && localProvider(cfg.llm.provider) && models.key !== modelKey && models.st !== "loading") {
      const t = setTimeout(discoverModels, 400); // after typing a port or URL
      return () => clearTimeout(t);
    }
  }, [tab, cfg, modelKey, models.key, models.st, discoverModels]);

  const set = (path: string, value: unknown) => {
    setCfg((c) => (c ? setAt(c, path, value) : c));
    setEvent(page, null);
  };

  const svcOnline = (x: Svc): boolean | null => {
    const r = tests[x];
    if (r?.st === "ok") return true;
    if (r?.st === "error") return false;
    if (!status) return null;
    if (x === "llm") return status.llm.online;
    if (x === "ise") return status.ise.online;
    if (x === "pxgrid") return status.ise.pxgrid.error ? false : null;
    return status.netflow.online;
  };

  // ---- certificate generation (explicit click; the import into ISE is audited server-side)
  async function generate() {
    if (!cfg || gen.busy) return;
    setGen({ busy: true });
    try {
      const r = await post<{ client_cert: string; client_key: string; info: CertInfo; trust_import: TrustImport }>(
        "/ise/pxgrid/certificate", { config: cfg });
      setCfg((c) => (c ? setAt(setAt(c, "ise.pxgrid.client_cert", r.client_cert), "ise.pxgrid.client_key", r.client_key) : c));
      setGen({ busy: false, info: r.info, trust: r.trust_import });
    } catch (e) {
      setGen({ busy: false, error: (e as Error).message });
    }
  }

  const sections = useMemo(() => {
    if (!cfg) return null;
    const { isInt, host, absPath, url } = checks(s);
    const L = s.llm, I = s.ise, C = s.collector, G = s.lang;
    const local = localProvider(cfg.llm.provider);
    const px = cfg.ise.pxgrid;
    const nodeOk = nodes.st === "ok" && nodes.pan === cfg.ise.pan.trim();
    const nodeOpts = (exclude: string) => nodes.list.filter((n) => n.fqdn !== exclude).map((n) => [n.fqdn, `${n.fqdn} · ${n.ip}`] as [string, string]);
    const withCurrent = (opts: [string, string][], value: string) => (value && !opts.some(([v]) => v === value) ? [...opts, [value, value] as [string, string]] : opts);
    const apiUrl = `https://${cfg.ise.pan.trim() || "<PAN>"}:${cfg.ise.openapi.port || 443}/ers`;
    const modelOpts: [string, string][] = [
      ...(cfg.llm.model ? [] : [["", s.mdSelect] as [string, string]]),
      ...(models.key === modelKey ? models.list : []).map((x) => [x.name, [x.name, sizeOf(x.size, m.locale), x.quantization,
        x.loaded && cfg.llm.provider === "ollama" ? s.mdLoaded : ""].filter(Boolean).join(" · ")] as [string, string]),
    ];
    const mdApi = cfg.llm.provider === "ollama" ? "GET /api/tags" : "GET /v1/models";
    const mdHelp = models.key === modelKey && models.st === "loading" ? s.mdRefreshing
      : models.key === modelKey && models.st === "error" ? models.msg ?? s.mdBadUrl : s.mdListHelp(mdApi);

    // pxGrid nodes: a dropdown once the cluster is scanned, typed in if the scan failed.
    const nodeField = (path: string, label: string, value: string, exclude: string, required: boolean, help: string): Field =>
      nodeOk
        ? { path, label, kind: "select", required, help,
            options: path.endsWith("secondary_node")
              ? withCurrent([["", I.none], ...nodeOpts(exclude)], value)
              : withCurrent(value ? nodeOpts(exclude) : [["", I.nodePick], ...nodeOpts(exclude)], value) }
        : nodes.st === "error"
          ? { path, label, mono: true, required, check: host, help: I.nodeManualHelp, placeholder: "ise-px1.example.local" }
          : { path, label, kind: "select", disabled: true, help, options: [[value, value || (path.endsWith("secondary_node") ? I.none : I.nodePick)]] };

    const certMsg = (() => {
      const info = gen.info ?? (px.client_cert && certs.client?.path === px.client_cert ? certs.client : null);
      if (gen.error) return { text: gen.error, tone: "err" as const };
      if (!info) return { text: I.genNeed, tone: "warn" as const };
      const trust = gen.info ? gen.trust : certs.trust_import?.sha256 === info.sha256 ? certs.trust_import : null;
      let text = I.genDone(info.subject, day(info.not_after), shortFp(info.sha256));
      if (trust?.status === "ok") text += I.pushDone(trust.pan ?? cfg.ise.pan);
      else if (trust?.status === "failed") text += I.pushFailed(trust.error ?? "");
      else if (!px.import_to_ise_trust) text += I.pushManual;
      if (saved && px.client_cert !== saved.ise.pxgrid.client_cert) text += I.genUnsaved;
      return { text, tone: trust?.status === "failed" ? ("err" as const) : trust?.status === "ok" ? ("ok" as const) : ("warn" as const) };
    })();

    const out: Record<Tab, { label: string; title: string; desc: string; sections: Section[] }> = {
      llm: {
        label: L.label, title: L.title, desc: L.desc,
        sections: [
          {
            title: L.provider,
            note: cloudProvider(cfg.llm.provider) ? { tone: "warn", text: L.cloudNote } : undefined,
            fields: [
              { path: "llm.provider", label: L.providerLabel, kind: "select", options: Object.entries(L.providers) },
              local && { path: "llm.location", label: L.location, kind: "select", options: Object.entries(L.locations) },
              local && cfg.llm.location === "local"
                ? { path: "llm.port", label: L.port, kind: "number", required: true, mono: true, check: isInt(1, 65535), help: L.portHelp(llmUrl),
                    placeholder: cfg.llm.provider === "ollama" ? "11434" : "8000" }
                : { path: "llm.endpoint", label: L.endpoint, required: true, mono: true, check: url, placeholder: "http://ollama:11434" },
              local
                ? { path: "llm.model", label: L.model, kind: "select", required: true, onOpen: discoverModels, help: mdHelp,
                    options: withCurrent(modelOpts, cfg.llm.model) }
                : { path: "llm.model", label: cfg.llm.provider === "azure" ? L.deployment : L.model, required: true, mono: true },
              cfg.llm.provider !== "ollama" && { path: "llm.api_key", label: L.apiKey, kind: "password", required: cfg.llm.provider !== "openai", help: L.apiKeyHelp },
              cfg.llm.provider === "azure" && { path: "llm.api_version", label: L.apiVersion, mono: true },
              { path: "llm.timeout_s", label: L.timeout, kind: "number", mono: true, check: isInt(1, 600) },
            ],
          },
          {
            title: L.trigger,
            fields: [
              { path: "llm.trigger", label: L.mode, kind: "select", options: Object.entries(L.triggers) },
              cfg.llm.trigger === "scheduled" && { path: "llm.scheduled_minutes", label: L.interval, kind: "number", mono: true, check: isInt(5, 1440) },
              { path: "llm.learning_days", label: L.learning, kind: "number", mono: true, check: isInt(0, 90), help: L.learningHelp },
            ],
          },
        ],
      },
      ise: {
        label: I.label, title: I.title, desc: I.desc,
        sections: keep([
          {
            sub: "cluster", title: I.openapi,
            fields: [
              { path: "ise.pan", label: I.pan, required: true, mono: true, check: host, placeholder: "ise-pan.example.local", help: I.panHelp(apiUrl) },
              { path: "ise.openapi.port", label: I.port, kind: "number", mono: true, check: isInt(1, 65535) },
              { path: "ise.openapi.username", label: I.user, required: true, mono: true, help: I.userHelp },
              { path: "ise.openapi.password", label: I.password, kind: "password", required: true, help: I.passwordHelp },
            ],
          },
          {
            sub: "cluster", title: I.caTitle,
            fields: [
              { path: "ise.ca_cert", label: I.caFile, kind: "file", help: I.caFileHelp, upload: { kind: "ca", accept: ".pem,.crt,.cer", info: certs.ca } },
              { path: "ise.verify_tls", label: I.verifyTls, kind: "toggle", help: I.verifyTlsHelp },
            ],
          },
          {
            sub: "pxgrid", title: I.pxConn,
            note: nodeOk ? { tone: "info", text: I.scanned(nodes.total, nodes.list.length) }
              : nodes.st === "loading" ? { tone: "info", text: s.discoveringOn(nodes.pan) }
              : nodes.st === "error" ? { tone: "warn", text: I.scanFailed(nodes.msg ?? "") }
              : { tone: "info", text: I.nodeNeedScan },
            fields: [
              nodeField("ise.pxgrid.node", I.node, px.node, "", !px.base_url, I.nodeDiscoveredHelp),
              nodeField("ise.pxgrid.secondary_node", I.node2, px.secondary_node, px.node, false, I.node2Help),
              { path: "ise.pxgrid.client_name", label: I.clientName, required: true, mono: true, help: I.clientNameHelp },
              { path: "ise.pxgrid.auth", label: I.auth, kind: "select", options: Object.entries(I.auths) },
              px.auth === "password" && { path: "ise.pxgrid.password", label: I.pxPassword, kind: "password", help: I.pxPasswordHelp },
              { path: "ise.pxgrid.subscribe", label: I.subscribe, kind: "toggle" },
            ],
          },
          px.auth === "certificate" && {
            sub: "pxgrid", title: I.certTitle,
            fields: [
              { path: "ise.pxgrid.cert_mode", label: I.certMode, kind: "select", options: Object.entries(I.certModes) },
              px.cert_mode === "generate" && { path: "ise.pxgrid.cert_cn", label: I.cn, mono: true, placeholder: px.client_name },
              px.cert_mode === "generate" && { path: "ise.pxgrid.cert_days", label: I.validity, kind: "number", mono: true, check: isInt(1, 3650) },
              px.cert_mode === "upload" && { path: "ise.pxgrid.client_cert", label: I.certFile, kind: "file", required: true,
                upload: { kind: "client_cert", accept: ".pem,.crt,.cer", info: certs.client?.path === px.client_cert ? certs.client : null } },
              px.cert_mode === "upload" && { path: "ise.pxgrid.client_key", label: I.keyFile, kind: "file", required: true,
                upload: { kind: "client_key", accept: ".key,.pem" } },
              px.cert_mode === "upload" && { path: "ise.pxgrid.client_key_password", label: I.keyPass, kind: "password", help: I.keyPassHelp },
            ],
          },
          // Generation button on its own line, right under the CN and validity fields.
          px.auth === "certificate" && px.cert_mode === "generate" && {
            sub: "pxgrid",
            note: { tone: certMsg.tone === "ok" ? "info" : certMsg.tone === "err" ? "err" : "warn", text: certMsg.text },
            action: (
              <button type="button" className="btn outline" onClick={generate} disabled={gen.busy}>
                <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="5.5" cy="10.5" r="3" /><path d="M7.7 8.3L14 2M11.5 4.5l1.5 1.5M10 6l1.2 1.2" />
                </svg>
                {gen.busy ? I.generating : px.client_cert ? I.regenerate : I.generate}
              </button>
            ),
            fields: [{ path: "ise.pxgrid.import_to_ise_trust", label: I.pushIse, kind: "toggle", help: I.pushIseHelp }],
          },
          {
            sub: "advanced", title: I.writePolicy,
            note: cfg.ise.write_mode === "enforce" ? { tone: "warn", text: I.enforceNote } : { tone: "info", text: I.monitorNote },
            fields: [
              { path: "ise.write_mode", label: I.writeMode, kind: "select", options: Object.entries(I.writeModes) },
              { path: "ise.sgacl_prefix", label: I.prefix, required: true, mono: true, check: (v) => (/^[A-Za-z][A-Za-z0-9_]*$/.test(v) ? "" : I.prefixCheck), help: I.prefixHelp },
            ],
          },
          {
            sub: "advanced", title: I.matrixTitle,
            fields: [
              { path: "ise.reconcile_minutes", label: I.reconcile, kind: "number", mono: true, check: isInt(1, 1440), help: I.reconcileHelp },
              { path: "ise.matrix_default", label: I.matrixDefault, kind: "select", options: Object.entries(I.matrixDefaults), help: I.matrixDefaultHelp },
              { path: "ise.egress_firewall", label: I.egressFw, kind: "toggle", help: I.egressFwHelp },
            ],
          },
          {
            sub: "advanced", title: I.labTitle,
            fields: [
              { path: "ise.openapi.base_url", label: I.baseUrl, mono: true, check: url, help: I.baseUrlHelp },
              { path: "ise.pxgrid.base_url", label: I.pxBaseUrl, mono: true, check: url, help: I.pxBaseUrlHelp },
            ],
          },
        ]),
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
              { path: "collector.allowed_exporters", label: C.exporters, kind: "list", mono: true, help: C.exportersHelp,
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
      lang: {
        label: G.label, title: G.title, desc: G.desc,
        sections: [
          {
            title: G.interface,
            fields: [
              { path: "ui.language", label: G.uiLanguage, help: G.uiLanguageHelp, kind: "select", maxWidth: 200,
                options: [["fr", MESSAGES.fr.langName], ["en", MESSAGES.en.langName]] },
            ],
          },
        ],
      },
    };
    return out;
  }, [cfg, saved, s, m.locale, nodes, models, modelKey, llmUrl, certs, gen, discoverModels]);

  if (!cfg || !saved || !sections) return <div className="card">{s.loading}</div>;

  const valueOf = (f: Field) => {
    const v = getAt(cfg, f.path);
    if (f.kind === "list") return (v as string[]).join(", ");
    return v === undefined || v === null ? "" : String(v);
  };
  const errorOf = (f: Field) => {
    if (f.kind === "toggle" || f.disabled) return "";
    const v = valueOf(f).trim();
    if (f.kind === "file") return f.required && !v && !files[f.path] ? s.required : "";
    if (f.kind === "password" && v === SECRET_MASK) return "";
    if (f.required && !v) return s.required;
    if (f.kind === "select") return "";
    return v && f.check ? f.check(v) : "";
  };
  const fieldsOf = (secs: Section[]) => secs.flatMap((x) => x.fields.filter(Boolean) as Field[]);
  const errCount = (t: Tab, sb?: Sub) => fieldsOf(sections[t].sections.filter((x) => !sb || x.sub === sb)).filter((f) => errorOf(f)).length;
  const totalErr = errCount("llm") + errCount("ise") + errCount("collector") + errCount("lang");
  const dirty = JSON.stringify(cfg) !== JSON.stringify(saved) || Object.keys(files).length > 0;
  const svc = PAGE_SVC[page];
  const testErrors = (p: Page) => (p === "llm" ? errCount("llm") : p === "collector" ? errCount("collector")
    : p === "ise:pxgrid" ? errCount("ise", "pxgrid") + errCount("ise", "cluster") : errCount("ise", "cluster"));

  const update = (f: Field, raw: string | boolean) => {
    if (f.kind === "number") set(f.path, raw === "" ? "" : Number(raw));
    else if (f.kind === "list") set(f.path, String(raw).split(",").map((x) => x.trim()).filter(Boolean));
    else set(f.path, raw);
    if (f.path.startsWith("llm.")) setTests((x) => ({ ...x, llm: undefined }));
    if (f.path.startsWith("ise.pxgrid.") && f.path !== "ise.pxgrid.import_to_ise_trust") setTests((x) => ({ ...x, pxgrid: undefined }));
  };

  async function testService(target: Svc, conf: Config): Promise<{ ok: boolean; message: string }> {
    try {
      return await post<{ ok: boolean; message: string }>(`/config/test/${target}`, { config: conf });
    } catch (e) {
      return { ok: false, message: (e as Error).message };
    }
  }

  async function runTest() {
    if (!svc || !cfg) return;
    const p = page;
    setEvent(p, { kind: "test" });
    if (testErrors(p)) return setTests((x) => ({ ...x, [svc]: { st: "error", msg: s.fixBeforeTest } }));
    setTests((x) => ({ ...x, [svc]: { st: "testing", msg: s.testRunning } }));
    const r = await testService(svc, cfg);
    setTests((x) => ({ ...x, [svc]: { st: r.ok ? "ok" : "error", msg: r.message } }));
    onChanged();
  }

  async function resync() {
    const p = page;
    setEvent(p, { kind: "sync", st: "syncing" });
    try {
      await post("/ise/sync");
      setEvent(p, { kind: "sync", st: "ok" });
    } catch (e) {
      setEvent(p, { kind: "sync", st: "error", msg: s.syncFailed((e as Error).message) });
    }
    onChanged();
  }

  async function save() {
    if (!cfg || !saved) return;
    const p = page;
    const target = PAGE_SVC[p];
    setEvents({ [p]: { kind: "save", st: "saving" } });
    let body = cfg;
    let r: Config;
    try {
      for (const [path, f] of Object.entries(files)) {
        const pw = f.kind === "client_key" && cfg.ise.pxgrid.client_key_password !== SECRET_MASK ? cfg.ise.pxgrid.client_key_password : "";
        const up = await post<{ path: string }>("/ise/certificates/upload", { kind: f.kind, filename: f.name, data: await toBase64(f.file), password: pw });
        body = setAt(body, path, up.path);
      }
      r = await put<Config>("/config", { config: body });
    } catch (e) {
      const detail = e instanceof ApiError && Array.isArray(e.body.detail)
        ? (e.body.detail as { loc: string[]; msg: string }[]).map((d) => `${d.loc.join(".")} : ${d.msg}`).join(" · ")
        : (e as Error).message;
      setEvents({ [p]: { kind: "save", st: "refused", msg: s.saveRefused(detail) } });
      return;
    }
    const before = saved.ise;
    const clusterChanged = before.pan !== r.ise.pan || before.openapi.port !== r.ise.openapi.port ||
      before.openapi.username !== r.ise.openapi.username || cfg.ise.openapi.password !== SECRET_MASK;
    setSaved(r);
    setCfg(r);
    setFiles({});
    setGen((g) => ({ busy: false, info: g.info, trust: g.trust }));
    setLang(r.ui.language);
    onChanged();
    loadCerts();
    if ((clusterChanged || nodes.st !== "ok" || nodes.pan !== r.ise.pan) && r.ise.pan) {
      scan(r, true);
    }
    if (!target) return setEvents({ [p]: { kind: "save", st: "done" } });
    setEvents({ [p]: { kind: "save", st: "testing", svc: target } });
    const res = await testService(target, r);
    setTests((x) => ({ ...x, [target]: { st: res.ok ? "ok" : "error", msg: res.message } }));
    setEvents({ [p]: { kind: "save", st: res.ok ? "ok" : "ko", svc: target, msg: res.message } });
    onChanged();
  }

  // ---- status bar of the current page: the latest event replaces the previous message; without
  // a recent event it shows the page state.
  const S = MESSAGES[lang].settings;
  const st = status;
  const sync = st?.ise.online ? m.header.synced(ago(st.ise.last_sync), st.ise.sgacl_count, st.ise.cell_count) : m.header.notSynced;
  const downText = (x: Svc): string => {
    if (!st) return "";
    if (x === "llm") return st.llm.error ?? s.llmTimeout(st.llm.timeout_s, st.llm.endpoint);
    if (x === "ise") return s.iseDown(st.ise.pan, st.ise.last_error ?? "");
    if (x === "pxgrid") return s.pxgridDown(st.ise.pxgrid.error ?? "");
    return s.collectorNoFlow(st.netflow.stale_after_seconds);
  };
  let note: { text: string; tone: Tone } | null = null;
  const ev = events[page];
  const t = svc ? tests[svc] : undefined;
  if (ev?.kind === "test" && t) note = { text: t.msg, tone: t.st === "ok" ? "ok" : t.st === "error" ? "error" : "info" };
  else if (ev?.kind === "save") {
    note = ev.st === "saving" ? { text: s.saving, tone: "info" }
      : ev.st === "testing" ? { text: S.savedTesting(S.savedWhat[ev.svc!]), tone: "info" }
      : ev.st === "ok" ? { text: S.savedOk[ev.svc!], tone: "ok" }
      : ev.st === "ko" ? { text: S.savedKo(ev.msg ?? ""), tone: "error" }
      : ev.st === "refused" ? { text: ev.msg ?? "", tone: "error" }
      : { text: S.saved, tone: "ok" };
  } else if (ev?.kind === "sync") {
    note = ev.st === "syncing" ? { text: m.header.syncing, tone: "info" } : ev.st === "error" ? { text: ev.msg ?? "", tone: "error" } : { text: sync, tone: "ok" };
  }
  if (!note) {
    if (totalErr) note = { text: s.fixToSave, tone: "error" };
    else if (dirty) note = { text: s.unsaved, tone: "warn" };
    else if (svc && svcOnline(svc) === false) note = { text: t?.st === "error" ? t.msg : downText(svc), tone: "error" };
    else if (page === "ise:cluster") note = { text: sync, tone: "muted" };
    else note = { text: s.upToDate, tone: "muted" };
  }
  const toneColor: Record<Tone, string> = { ok: "var(--ok-fg)", error: "var(--bad-fg)", warn: "var(--warn-fg)", info: "var(--info-fg)", muted: "var(--text-3)" };

  const tabs: Tab[] = ["llm", "ise", "collector", "lang"];
  const tabSvc: Record<Tab, Svc | null> = { llm: "llm", ise: "ise", collector: "collector", lang: null };
  const where = cloudProvider(saved.llm.provider) ? "cloud" : saved.llm.location === "local" && localProvider(saved.llm.provider) ? "local" : "remote";
  const testLabel: Record<Svc, string> = { llm: s.testLlm, ise: s.testIse, pxgrid: s.testPx, collector: s.testCollector };
  const subs: Sub[] = ["cluster", "pxgrid", "advanced"];
  const visible = sections[tab].sections.filter((x) => tab !== "ise" || x.sub === sub);

  return (
    <section className="card settings" aria-label={s.aria}>
      <nav aria-label={s.navAria}>
        <h2 style={{ marginBottom: 8 }}>{s.title}</h2>
        {tabs.map((tb) => {
          const e = errCount(tb);
          const sv = tabSvc[tb];
          const testing = sv && (tests[sv]?.st === "testing" || (tb === "ise" && tests.pxgrid?.st === "testing"));
          const online = sv ? svcOnline(sv) !== false && (tb !== "ise" || tests.pxgrid?.st !== "error") : true;
          const color = e ? "var(--danger)" : !sv ? "#596069" : testing ? "var(--pend)" : online ? "var(--ok)" : "var(--danger)";
          const detail = tb === "llm" ? `${s.llm.where[where]} · ${saved.llm.model || s.mdNone}`
            : tb === "ise" ? sync : st ? s.flowRate(String(st.netflow.flows_per_s)) : "";
          const state = sv && svcOnline(sv) === null && tb === "llm" ? "…" : online ? s.online : s.offline;
          return (
            <button key={tb} type="button" className="tab" aria-current={tb === tab ? "page" : undefined} onClick={() => setTab(tb)}>
              <span style={{ flexGrow: 1, display: "flex", flexDirection: "column", gap: 2 }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>{sections[tb].label}</span>
                <span className="small muted">
                  {e ? s.toFix(e) : !sv ? s.globalSetting : testing ? s.testing : `${state} · ${detail}`}
                </span>
              </span>
              <span className="sdot" style={{ background: color }} />
            </button>
          );
        })}
        <p className="small muted" style={{ margin: "12px 0 0" }}>{s.secretsNote}</p>
      </nav>

      <div className="body">
        <div>
          <h3 style={{ fontSize: 18, fontWeight: 700 }}>{sections[tab].title}</h3>
          <p className="muted" style={{ margin: "4px 0 0", fontSize: 13 }}>{sections[tab].desc}</p>
        </div>

        {tab === "ise" && (
          <div role="tablist" aria-label={s.ise.subsAria} className="subtabs">
            {subs.map((x) => {
              const n = errCount("ise", x);
              return (
                <button key={x} type="button" role="tab" className="subtab" aria-selected={x === sub} onClick={() => setSub(x)}>
                  {s.ise.subs[x]}{n > 0 && <span className="count">{n}</span>}
                </button>
              );
            })}
          </div>
        )}

        {visible.map((sec, i) => (
          <fieldset key={(sec.title ?? "") + i}>
            {sec.title && <legend>{sec.title}</legend>}
            {sec.note && <div className={`note ${sec.note.tone}`}>{sec.note.text}</div>}
            {sec.action && <div className="action-row">{sec.action}</div>}
            <div className="grid-fields">
              {(sec.fields.filter(Boolean) as Field[]).map((f) => {
                const id = "cfg-" + f.path.replace(/\./g, "-");
                const err = errorOf(f);
                if (f.kind === "toggle") {
                  return (
                    <div key={f.path} className="field full">
                      <label className="check" htmlFor={id}>
                        <input id={id} type="checkbox" disabled={f.disabled} checked={!!getAt(cfg, f.path)}
                          onChange={(e) => !f.disabled && update(f, e.target.checked)} />
                        <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                          <span style={{ fontSize: 13, fontWeight: 600 }}>{f.label}</span>
                          {f.help && <span className="help">{f.help}</span>}
                        </span>
                      </label>
                    </div>
                  );
                }
                let help = err || f.help || "";
                if (f.kind === "file") {
                  const pending = files[f.path];
                  const info = f.upload?.info;
                  const status = pending ? s.fileChosen(pending.name) : info ? s.fileCurrent(info.subject, day(info.not_after))
                    : valueOf(f) ? valueOf(f) : s.fileNone;
                  help = err ? `${err} · ${status}` : [status, f.help].filter(Boolean).join(" · ");
                }
                return (
                  <div key={f.path} className="field">
                    <label className="field-label" htmlFor={id}>{f.label}{f.required ? " *" : ""}</label>
                    {f.kind === "select" ? (
                      <select id={id} className="input" value={valueOf(f)} disabled={f.disabled} aria-describedby={id + "-help"}
                        style={f.maxWidth ? { maxWidth: f.maxWidth } : undefined}
                        onMouseDown={f.onOpen} onFocus={f.onOpen}
                        onChange={(e) => update(f, e.target.value)}>
                        {f.options!.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                      </select>
                    ) : f.kind === "file" ? (
                      <input id={id} type="file" accept={f.upload?.accept} className={`file-input ${err ? "invalid" : ""}`}
                        aria-describedby={id + "-help"} aria-invalid={!!err}
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          setFiles((x) => {
                            const out = { ...x };
                            if (file && f.upload) out[f.path] = { name: file.name, kind: f.upload.kind, file };
                            else delete out[f.path];
                            return out;
                          });
                          setEvent(page, null);
                        }} />
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

        <div className="page-bar">
          {svc && (
            <button type="button" id={`test-${svc}`} className="btn outline" onClick={runTest} disabled={t?.st === "testing"}>
              {t?.st === "testing" ? s.testing : testLabel[svc]}
            </button>
          )}
          {page === "ise:cluster" && (
            <button type="button" className="btn outline" onClick={resync} disabled={ev?.kind === "sync" && ev.st === "syncing"}
              title={s.autoSync(saved.ise.reconcile_minutes)}>
              <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M13 8a5 5 0 0 1-8.5 3.5M3 8a5 5 0 0 1 8.5-3.5" /><path d="M11.5 2v2.5H9M4.5 14v-2.5H7" />
              </svg>
              {s.resyncMatrix}
            </button>
          )}
          <span style={{ flexGrow: 1 }} />
          <span role="status" aria-live="polite" className="small" style={{ color: toneColor[note.tone], maxWidth: 520 }}>{note.text}</span>
          {dirty && (
            <button type="button" className="btn link" onClick={() => { setCfg(saved); setFiles({}); setTests({}); setEvents({}); }}>
              {s.discard}
            </button>
          )}
          <button type="button" className="btn ok" disabled={!dirty || totalErr > 0} onClick={save}>{s.save}</button>
        </div>
      </div>
    </section>
  );
}
