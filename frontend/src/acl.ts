// Client-side mirror of backend/matrix_advisor/policy/acl.py, for instant feedback while
// editing. The backend re-validates everything before writing to ISE.

export interface Ace {
  action: "permit" | "deny";
  proto: "tcp" | "udp" | "icmp" | "ip";
  lo: number | null;
  hi: number | null;
}

const ACE_RE =
  /^(permit|deny)\s+(tcp|udp|icmp|ip)(?:\s+dst\s+(?:eq\s+(\d{1,5})|range\s+(\d{1,5})\s+(\d{1,5})))?(?:\s+log)?$/i;

export function parse(text: string): { rules: Ace[]; errors: string[] } {
  const rules: Ace[] = [];
  const errors: string[] = [];
  text.split("\n").forEach((raw, i) => {
    const line = raw.replace(/^\s*\+?\s*/, "").trim();
    if (!line || line.startsWith("!") || line.startsWith("#")) return;
    const m = line.match(ACE_RE);
    if (!m) {
      errors.push(`Ligne ${i + 1} : « ${line} » n’est pas une ACE reconnue.`);
      return;
    }
    const proto = m[2].toLowerCase() as Ace["proto"];
    const lo = m[3] ? +m[3] : m[4] ? +m[4] : null;
    const hi = m[3] ? +m[3] : m[5] ? +m[5] : null;
    if (lo !== null && (lo < 1 || (hi ?? 0) > 65535 || (hi ?? 0) < lo)) {
      errors.push(`Ligne ${i + 1} : port hors plage.`);
      return;
    }
    if (lo !== null && proto !== "tcp" && proto !== "udp") {
      errors.push(`Ligne ${i + 1} : un port n’a de sens qu’avec tcp ou udp.`);
      return;
    }
    rules.push({ action: m[1].toLowerCase() as Ace["action"], proto, lo, hi });
  });
  if (!rules.length && !errors.length) errors.push("Le contrat est vide.");
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

export function validate(text: string, observed: string[]) {
  const { rules, errors } = parse(text);
  const warns: string[] = [];
  const infos: string[] = [];
  if (rules.some((r) => r.action === "permit" && r.proto === "ip"))
    warns.push("« permit ip » ouvre tout le trafic entre ces deux groupes : contraire au deny par défaut.");
  if (!errors.length) {
    for (const spec of observed) if (!allows(rules, spec)) warns.push(`${spec} est observé mais n’est plus autorisé : ce trafic sera bloqué.`);
    for (const r of rules) {
      if (r.action !== "permit" || r.lo === null) continue;
      const seen = observed.some((s) => {
        const [p, a, b] = parseSpec(s);
        return p === r.proto && a !== null && a <= (r.hi ?? r.lo!) && (b ?? a) >= r.lo!;
      });
      if (!seen) infos.push(`${r.proto.toUpperCase()}/${r.lo === r.hi ? r.lo : `${r.lo}-${r.hi}`} autorisé mais jamais observé sur cette paire.`);
    }
    const last = rules[rules.length - 1];
    if (rules.length && !(last.action === "deny" && last.proto === "ip"))
      infos.push("Pas de « deny ip » final : c’est la politique par défaut de la cellule ou de la matrice qui s’applique.");
  }
  return { errors, warns, infos };
}

export const normalize = (text: string) =>
  text
    .split("\n")
    .map((l) => l.replace(/^\s*\+?\s*/, "").trim())
    .filter(Boolean)
    .join("\n");
