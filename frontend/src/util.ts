import type { LinkStatus, Risk } from "./types";

// Labels come from messages.ts (risk, status, kind); this maps them to chip styles.
export const RISK_CLS: Record<Risk, string> = { low: "ok", medium: "warn", high: "bad" };

export const STATUS_CLS: Record<LinkStatus, string> = {
  allowed: "ok",
  partial: "partial",
  pending: "warn",
  rejected: "grey",
};
