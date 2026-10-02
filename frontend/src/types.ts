export type Range = "24h" | "7d" | "30d";
export type LinkStatus = "allowed" | "partial" | "pending" | "rejected";
export type Kind = "extend" | "reuse" | "new" | "external";
export type Risk = "low" | "medium" | "high";

export interface Contract {
  id: string;
  name: string;
  acl: string;
  shared_with: string[];
}

export interface PortStat {
  spec: string;
  flows: number;
  hosts: number;
  covered: boolean;
}

export interface Link {
  id: string;
  src: string;
  dst: string;
  flows: number;
  bytes: number;
  hosts: number;
  status: LinkStatus;
  contracts: Contract[];
  monitor: boolean;
  first_seen: string | null;
  activity: Activity;
  rare: boolean;
  ports: PortStat[];
  blocked_flows: number;
  proposal_id: string | null;
  last_decision_id: string | null;
  risk: Risk | null;
  kind: Kind | null;
}

export interface Dashboard {
  range: Range;
  links: Link[];
  kpi: {
    pairs: number;
    allowed: number;
    partial: number;
    coverage_pct: number;
    pending: number;
    pending_by_kind: Partial<Record<Kind, number>>;
    rejected: number;
    blocked_flows: number;
    total_flows: number;
  };
  trend: { ts: string; uncovered: number }[];
  learning: Learning;
  observation: Observation;
}

// Days with traffic for one pair, out of the days of history in the window.
export interface Activity {
  days_seen: number;
  observed_days: number;
  last_seen_days_ago: number | null;
}

// Whether the history is long enough for monthly jobs to have been seen before default-deny.
export interface Observation {
  days: number;
  recommended_days: number;
  retention_days: number;
  sufficient: boolean;
}

export interface Learning {
  active: boolean;
  started: string | null;
  ends_at: string | null;
}

export interface Proposal {
  id: string;
  src: string;
  dst: string;
  kind: Kind;
  base_contract: string | null;
  base_sgacl_id: string | null;
  specs: string[];
  proposed_acl: string;
  edited_acl: string | null;
  risk: Risk;
  recommendation: "approve" | "review" | "reject";
  justification: string;
  features: {
    total_flows: number;
    source_hosts: number;
    first_seen: string | null;
    ports: { spec: string; flows: number; hosts: number }[];
    heuristics: string[];
    new_name: string;
  };
  status: "pending" | "approved" | "rejected" | "superseded";
  mode: "clone" | "inplace" | null;
  result: Record<string, string> | null;
  llm_used: boolean;
  created_at: string;
  decided_at: string | null;
}

export interface Analysis {
  acl: string;
  validation: { errors: string[]; warns: string[]; infos: string[] };
  edited: boolean;
  changes_base: boolean;
  base_contract: string | null;
  others: { src: string; dst: string }[];
  impacts: { src: string; dst: string; spec: string; flows: number }[];
  default_mode: "clone" | "inplace";
  inplace_allowed: boolean;
  clone_name: string | null;
  new_name: string;
  write_mode: "monitor" | "enforce";
}

export interface Status {
  netflow: { online: boolean; last_record: string | null; flows_per_s: number };
  ise: {
    online: boolean;
    last_sync: string | null;
    last_error: string | null;
    sgacl_count: number;
    cell_count: number;
    pxgrid: { state: string; error: string | null; mode: string | null };
  };
  llm: { online: boolean | null; provider: string; model: string; cloud: boolean; error: string | null };
  learning: Learning;
  observation: Observation;
  write_mode: "monitor" | "enforce";
  prefix: string;
}

// Configuration as returned by GET /api/config (secrets masked).
export interface Config {
  llm: {
    provider: "ollama" | "openai" | "anthropic" | "azure";
    endpoint: string;
    model: string;
    api_key: string;
    api_version: string;
    temperature: number;
    timeout_s: number;
    trigger: "event" | "scheduled";
    scheduled_minutes: number;
    learning_days: number;
    language: string;
    send_ip_addresses: false;
  };
  ise: {
    pan: string;
    openapi: { base_url: string; username: string; password: string; port: number; verify_tls: boolean; ca_cert: string };
    pxgrid: {
      node: string;
      base_url: string;
      client_name: string;
      auth: "certificate" | "password";
      client_cert: string;
      client_key: string;
      ca_cert: string;
      password: string;
      port: number;
      verify_tls: boolean;
      subscribe: boolean;
      poll_seconds: number;
    };
    write_mode: "monitor" | "enforce";
    sgacl_prefix: string;
    reconcile_minutes: number;
    matrix_default: "deny" | "permit";
    static_bindings: Record<string, string>;
  };
  collector: {
    type: "goflow2";
    input_file: string;
    listen: string;
    ipfix_port: number;
    netflow_v9_port: number;
    allowed_exporters: string[];
    parquet_dir: string;
    duckdb_path: string;
    rotate_minutes: number;
    retention_days: number;
    aggregation_seconds: number;
    stale_after_seconds: number;
    sgt_source: "auto" | "ip";
  };
  server?: Record<string, unknown>;
}
