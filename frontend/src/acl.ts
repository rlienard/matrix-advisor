// Client-side mirror of backend/matrix_advisor/policy/acl.py, for instant feedback while
// editing. The backend re-validates everything before writing to ISE.

export interface Ace {
  action: "permit" | "deny";
  proto: "tcp" | "udp" | "icmp" | "ip";
  lo: number | null;
  hi: number | null;
}

// Same wording as MESSAGES in acl.py (checked by backend/tests/fixtures/acl_parity.json).
export type AclLang = "fr" | "en";
const MSG = {
  fr: {
    notAce: (i: number, line: string) => `Ligne ${i} : « ${line} » n’est pas une ACE reconnue.`,
    portRange: (i: number) => `Ligne ${i} : port hors plage.`,
    portProto: (i: number) => `Ligne ${i} : un port n’a de sens qu’avec tcp ou udp.`,
    empty: "Le contrat est vide.",
    permitAny: "« permit ip » ouvre tout le trafic entre ces deux groupes : contraire au deny par défaut.",
    blocked: (spec: string) => `${spec} est observé mais n’est plus autorisé : ce trafic sera bloqué.`,
    unobserved: (spec: string) => `${spec} autorisé mais jamais observé sur cette paire.`,
    noFinalDeny: "Pas de « deny ip » final : c’est la politique par défaut de la cellule ou de la matrice qui s’applique.",
  },
  en: {
    notAce: (i: number, line: string) => `Line ${i}: “${line}” is not a recognised ACE.`,
    portRange: (i: number) => `Line ${i}: port out of range.`,
    portProto: (i: number) => `Line ${i}: a port only makes sense with tcp or udp.`,
    empty: "The contract is empty.",
    permitAny: "“permit ip” opens all traffic between these two groups: contrary to default deny.",
    blocked: (spec: string) => `${spec} is observed but no longer permitted: this traffic will be blocked.`,
    unobserved: (spec: string) => `${spec} permitted but never observed on this pair.`,
    noFinalDeny: "No final “deny ip”: the default policy of the cell or the matrix applies.",
  },
};

const ACE_RE =
  /^(permit|deny)\s+(tcp|udp|icmp|ip)(?:\s+dst\s+(?:eq\s+(\d{1,5})|range\s+(\d{1,5})\s+(\d{1,5})))?(?:\s+log)?$/i;

export function parse(text: string, lang: AclLang = "fr"): { rules: Ace[]; errors: string[] } {
  const t = MSG[lang] ?? MSG.fr;
  const rules: Ace[] = [];
  const errors: string[] = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.replace(/^\s*\+?\s*/, "").trim();
    if (!line || line.startsWith("!") || line.startsWith("#")) return;
    const m = line.match(ACE_RE);
    if (!m) {
      errors.push(t.notAce(i + 1, line));
      return;
    }
    const proto = m[2].toLowerCase() as Ace["proto"];
    const lo = m[3] ? +m[3] : m[4] ? +m[4] : null;
    const hi = m[3] ? +m[3] : m[5] ? +m[5] : null;
    if (lo !== null && (lo < 1 || (hi ?? 0) > 65535 || (hi ?? 0) < lo)) {
      errors.push(t.portRange(i + 1));
      return;
    }
    if (lo !== null && proto !== "tcp" && proto !== "udp") {
      errors.push(t.portProto(i + 1));
      return;
    }
    rules.push({ action: m[1].toLowerCase() as Ace["action"], proto, lo, hi });
  });
  if (!rules.length && !errors.length) errors.push(t.empty);
  return { rules, errors };
}

function parseSpec(spec: string): [string, number | null, number | null] {
  if (!spec.includes("/")) return [spec.toLowerCase(), null, null];
  const [proto, port] = spec.split("/");
  const [a, b] = port.split("-");
  return [proto.toLowerCase(), +a, +(b ?? a)];
}

function covers(r: Ace, proto: string, port: number | null) {
  return (r.proto === "ip" || r.proto === proto) && (r.lo === null || (port !== null && port >= r.lo && port <= (r.hi ?? r.lo)));
}

export function allows(rules: Ace[], spec: string): boolean {
  const [proto, lo, hi] = parseSpec(spec);
  return [lo, hi].every((port) => {
    const hit = rules.find((r) => covers(r, proto, port));
    return !!hit && hit.action === "permit";
  });
}

// Specs (e.g. "TCP/22") of the permits that match none of the observed ports.
export function unobservedPermits(rules: Ace[], observed: string[]): string[] {
  const out: string[] = [];
  for (const r of rules) {
    if (r.action !== "permit" || r.lo === null) continue;
    const seen = observed.some((s) => {
      const [p, a, b] = parseSpec(s);
      return p === r.proto && a !== null && a <= (r.hi ?? r.lo!) && (b ?? a) >= r.lo!;
    });
    if (!seen) out.push(`${r.proto.toUpperCase()}/${r.lo === r.hi ? r.lo : `${r.lo}-${r.hi}`}`);
  }
  return out;
}

export function validate(text: string, observed: string[], lang: AclLang = "fr") {
  const t = MSG[lang] ?? MSG.fr;
  const { rules, errors } = parse(text, lang);
  const warns: string[] = [];
  const infos: string[] = [];
  if (rules.some((r) => r.action === "permit" && r.proto === "ip"))
    warns.push(t.permitAny);
  if (!errors.length) {
    for (const spec of observed) if (!allows(rules, spec)) warns.push(t.blocked(spec));
    for (const spec of unobservedPermits(rules, observed)) infos.push(t.unobserved(spec));
    const last = rules[rules.length - 1];
    if (rules.length && !(last.action === "deny" && last.proto === "ip"))
      infos.push(t.noFinalDeny);
  }
  return { errors, warns, infos };
}

export const normalize = (text: string) =>
  text
    .split("\n")
    .map((l) => l.replace(/^\s*\+?\s*/, "").trim())
    .filter(Boolean)
    .join("\n");
