import type { Kind, LinkStatus, Risk } from "./types";

export const fmt = (n: number) => Math.round(n).toLocaleString("fr-FR");

export const RISK: Record<Risk, { label: string; cls: string }> = {
  low: { label: "Profil attendu", cls: "ok" },
  medium: { label: "À restreindre", cls: "warn" },
  high: { label: "À vérifier", cls: "bad" },
};

export const STATUS: Record<LinkStatus, { label: string; cls: string }> = {
  allowed: { label: "Autorisé", cls: "ok" },
  partial: { label: "Partiellement couvert", cls: "partial" },
  pending: { label: "Non couvert", cls: "warn" },
  rejected: { label: "Rejeté", cls: "grey" },
};

export const KIND_LABEL: Record<Kind, string> = {
  extend: "extension",
  reuse: "réutilisation",
  new: "nouvelle",
  external: "hors matrice",
};

export function ago(iso: string | null | undefined): string {
  if (!iso) return "jamais";
  const s = (Date.now() - new Date(iso + (iso.endsWith("Z") ? "" : "Z")).getTime()) / 1000;
  if (s < 60) return "à l’instant";
  if (s < 3600) return `il y a ${Math.round(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.round(s / 3600)} h`;
  return `il y a ${Math.round(s / 86400)} j`;
}

export function shortDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso + (iso.endsWith("Z") ? "" : "Z")).toLocaleDateString("fr-FR", { day: "2-digit", month: "short" });
}
