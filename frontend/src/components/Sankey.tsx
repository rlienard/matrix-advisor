import { useMemo } from "react";
import type { Link } from "../types";
import { useI18n } from "../i18n";

const W = 1000;
const NODE_W = 12;
const GAP = 18;
const MAX_H = 440;

interface Props {
  links: Link[];
  selected: string | null;
  matches: (l: Link) => boolean;
  onSelect: (id: string) => void;
}

const COLORS: Record<string, string> = {
  allowed: "var(--ok)", partial: "var(--pend)", pending: "var(--pend)", rejected: "var(--rej)",
};

export default function Sankey({ links, selected, matches, onSelect }: Props) {
  const { m, fmt } = useI18n();
  const layout = useMemo(() => {
    const total = (key: "src" | "dst", name: string) => links.filter((l) => l[key] === name).reduce((t, l) => t + l.flows, 0);
    const srcs = [...new Set(links.map((l) => l.src))].sort((a, b) => total("src", b) - total("src", a));
    const dsts = [...new Set(links.map((l) => l.dst))].sort((a, b) => total("dst", b) - total("dst", a));
    const sum = links.reduce((t, l) => t + l.flows, 0) || 1;
    const gaps = Math.max(srcs.length, dsts.length) * GAP;
    const scale = Math.max(MAX_H - gaps, 120) / sum;
    const width = (l: Link) => Math.max(4, l.flows * scale);
    const side = (names: string[], key: "src" | "dst", other: "src" | "dst", order: string[]) =>
      names.map((name) => {
        const ls = links.filter((l) => l[key] === name).sort((a, b) => order.indexOf(a[other]) - order.indexOf(b[other]));
        return { name, ls, h: ls.reduce((t, l) => t + width(l), 0), flows: total(key, name) };
      });
    const left = side(srcs, "src", "dst", dsts);
    const right = side(dsts, "dst", "src", srcs);
    const height = (s: typeof left) => s.reduce((t, n) => t + n.h, 0) + GAP * Math.max(s.length - 1, 0);
    const H = Math.ceil(Math.max(height(left), height(right))) + 40;
    const ys: Record<string, { sy?: number; dy?: number; w: number }> = {};
    const place = (s: typeof left, key: "sy" | "dy") => {
      let y = 20 + (H - 40 - height(s)) / 2;
      return s.map((n) => {
        const node = { ...n, y };
        let off = y;
        for (const l of n.ls) {
          ys[l.id] = { ...(ys[l.id] ?? { w: width(l) }), [key]: off };
          off += width(l);
        }
        y += n.h + GAP;
        return node;
      });
    };
    return { left: place(left, "sy"), right: place(right, "dy"), ys, H };
  }, [links]);

  if (!links.length) return <div className="empty">{m.sankey.empty}</div>;
  const xm = W / 2;
  const f = (v: number) => v.toFixed(1);
  const halo = { paintOrder: "stroke", stroke: "var(--card)", strokeWidth: 4, strokeLinejoin: "round" } as const;

  return (
    <div style={{ overflowX: "auto" }}>
      <svg viewBox={`0 0 ${W} ${layout.H}`} style={{ display: "block", width: "100%", minWidth: 640, height: "auto" }}
        role="img" aria-label={m.sankey.aria}>
        {links.map((l) => {
          const p = layout.ys[l.id];
          const a = p.sy!, b = p.sy! + p.w, c = p.dy!, d = p.dy! + p.w;
          const match = matches(l);
          let op = l.status === "pending" ? 0.62 : l.status === "partial" ? 0.28 : l.status === "allowed" ? 0.3 : 0.22;
          if (selected === l.id) op = Math.max(op + 0.3, 0.6);
          if (!match) op = 0.06;
          return (
            <path key={l.id}
              d={`M${NODE_W} ${f(a)} C${xm} ${f(a)} ${xm} ${f(c)} ${W - NODE_W} ${f(c)} L${W - NODE_W} ${f(d)} C${xm} ${f(d)} ${xm} ${f(b)} ${NODE_W} ${f(b)} Z`}
              fill={COLORS[l.status]} fillOpacity={op}
              stroke={l.status === "partial" && match ? "var(--pend)" : "none"} strokeWidth={1.5} strokeDasharray="5 3"
              style={{ cursor: "pointer", transition: "fill-opacity .15s" }}
              onClick={() => onSelect(l.id)}>
              <title>{`${l.src} → ${l.dst} · ${m.sankey.flows(fmt(l.flows))} · ${m.status[l.status]}`}</title>
            </path>
          );
        })}
        {[...layout.left.map((n) => ({ ...n, left: true })), ...layout.right.map((n) => ({ ...n, left: false }))].map((n) => (
          <g key={(n.left ? "s:" : "d:") + n.name}>
            <rect x={n.left ? 0 : W - NODE_W} y={n.y} width={NODE_W} height={Math.max(n.h, 2)} rx={2} fill="#a7adb5" />
            <text x={n.left ? NODE_W + 8 : W - NODE_W - 8} y={n.y + n.h / 2 - 1} textAnchor={n.left ? "start" : "end"}
              style={{ ...halo, fill: "var(--text)", font: "600 14px var(--sans)" }}>{n.name}</text>
            <text x={n.left ? NODE_W + 8 : W - NODE_W - 8} y={n.y + n.h / 2 + 13} textAnchor={n.left ? "start" : "end"}
              style={{ ...halo, fill: "var(--text-3)", font: "400 11px var(--mono)" }}>{m.sankey.flows(fmt(n.flows))}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}
