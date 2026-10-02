import { useI18n } from "../i18n";
import type { Learning } from "../types";

interface Props {
  points: { ts: string; uncovered: number }[];
  live: number;
  rangeLabel: string;
  learning: Learning;
}

export default function Trend({ points, live, rangeLabel, learning }: Props) {
  const { m } = useI18n();
  const values = [...points.map((p) => p.uncovered), live];
  if (values.length < 2) values.unshift(live);
  const max = Math.max(10, Math.ceil(Math.max(...values) / 5) * 5);
  const x = (i: number) => 26 + (i * 288) / (values.length - 1);
  const y = (v: number) => 104 - (v / max) * 96;
  const pts = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  const last = values.length - 1;
  return (
    <svg viewBox="0 0 320 130" style={{ display: "block", width: "100%", height: "auto" }}
      role="img" aria-label={m.trend.aria}>
      {learning.active && (
        <>
          <rect x={26} y={8} width={288} height={96} fill="var(--raised)" />
          <text x={32} y={22} style={{ font: "500 9px var(--sans)", fill: "var(--text-3)" }}>{m.trend.learning}</text>
        </>
      )}
      <line x1={26} y1={104} x2={314} y2={104} stroke="var(--border)" />
      <line x1={26} y1={8} x2={314} y2={8} stroke="var(--divider)" />
      <text x={20} y={12} textAnchor="end" style={{ font: "400 9px var(--mono)", fill: "var(--text-3)" }}>{max}</text>
      <text x={20} y={107} textAnchor="end" style={{ font: "400 9px var(--mono)", fill: "var(--text-3)" }}>0</text>
      <path d={`M${x(0).toFixed(1)} 104 L${pts.join(" L")} L${x(last).toFixed(1)} 104 Z`} fill="var(--pend)" fillOpacity={0.14} />
      <polyline points={pts.join(" ")} fill="none" stroke="var(--pend)" strokeWidth={2} strokeLinejoin="round" />
      <circle cx={x(last)} cy={y(values[last])} r={3.5} fill="var(--pend)" stroke="var(--card)" strokeWidth={1.5} />
      <text x={26} y={122} style={{ font: "400 9px var(--mono)", fill: "var(--text-3)" }}>−{rangeLabel}</text>
      <text x={314} y={122} textAnchor="end" style={{ font: "400 9px var(--mono)", fill: "var(--text-3)" }}>{m.trend.now(live)}</text>
    </svg>
  );
}
