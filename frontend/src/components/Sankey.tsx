import { useMemo } from "react";
import type { Link, LinkStatus } from "../types";
import { useI18n } from "../i18n";

// Layout: thin start and end bars at the same distance from the edges of the panel, ribbons in
// a solid, semi-transparent status colour (no gradient). Each bar is made of one segment per
// ribbon, in the colour of that ribbon.
const W = 1000;
const BAR = 4;
const GAP = 18;
const MAX_H = 440;
const XM = W - BAR;

export const STATUS_COLOR: Record<LinkStatus, string> = {
  allowed: "var(--ok)",
  partial: "var(--part)",
  pending: "var(--pend)",
  rejected: "var(--rejected)",
};

interface Props {
  links: Link[];
  selected: string | null;
  matches: (l: Link) => boolean;
  onSelect: (id: string) => void;
}

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
  const f = (v: number) => v.toFixed(1);
  const xm = (BAR + XM) / 2;
  const halo = { paintOrder: "stroke", stroke: "#0d1014", strokeWidth: 4, strokeLinejoin: "round" } as const;
  const opacity = (l: Link) => {
    let op = l.status === "allowed" ? 0.42 : l.status === "rejected" ? 0.5 : 0.55;
    if (selected === l.id) op = Math.min(op + 0.3, 0.85);
    else if (selected) op *= 0.5;
    return matches(l) ? op : 0.06;
  };

  return (
    <div className="sankey-panel">
      <svg viewBox={`0 0 ${W} ${layout.H}`} style={{ display: "block", width: "100%", height: "auto", overflow: "visible" }}
        role="img" aria-label={m.sankey.aria}>
        {links.map((l) => {
          const p = layout.ys[l.id];
          const a = p.sy!, b = p.sy! + p.w, c = p.dy!, d = p.dy! + p.w;
          const match = matches(l);
          return (
            <path key={l.id}
              d={`M${BAR} ${f(a)} C${xm} ${f(a)} ${xm} ${f(c)} ${XM} ${f(c)} L${XM} ${f(d)} C${xm} ${f(d)} ${xm} ${f(b)} ${BAR} ${f(b)} Z`}
              fill={STATUS_COLOR[l.status]} fillOpacity={opacity(l)}
              stroke={l.status === "partial" && match ? "var(--part)" : "none"} strokeWidth={1.2} strokeDasharray="5 3"
              strokeOpacity={0.8}
              style={{ cursor: "pointer", transition: "fill-opacity .15s" }}
              onClick={() => onSelect(l.id)}>
              <title>{`${l.src} → ${l.dst} · ${m.sankey.flows(fmt(l.flows))} · ${m.status[l.status]}`}</title>
            </path>
          );
        })}
        {links.flatMap((l) => {
          const p = layout.ys[l.id];
          const style = { fill: STATUS_COLOR[l.status], fillOpacity: matches(l) ? 1 : 0.25, cursor: "pointer" };
          return [
            <rect key={"s:" + l.id} x={0} y={p.sy} width={BAR} height={p.w} style={style} onClick={() => onSelect(l.id)} />,
            <rect key={"d:" + l.id} x={XM} y={p.dy} width={BAR} height={p.w} style={style} onClick={() => onSelect(l.id)} />,
          ];
        })}
        {[...layout.left.map((n) => ({ ...n, left: true })), ...layout.right.map((n) => ({ ...n, left: false }))].map((n) => (
          <g key={(n.left ? "s:" : "d:") + n.name} pointerEvents="none">
            <text x={n.left ? BAR + 8 : XM - 8} y={n.y + n.h / 2 - 1} textAnchor={n.left ? "start" : "end"}
              style={{ ...halo, fill: "var(--text)", font: "600 13px var(--sans)" }}>{n.name}</text>
            <text x={n.left ? BAR + 8 : XM - 8} y={n.y + n.h / 2 + 13} textAnchor={n.left ? "start" : "end"}
              style={{ ...halo, fill: "var(--text-3)", font: "400 11px var(--mono)" }}>{m.sankey.flows(fmt(n.flows))}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}
