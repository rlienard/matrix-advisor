import { MESSAGES, type Lang } from "./messages";

// Language of the UI, sent with every request so that API error messages come back in it.
let language: Lang = "fr";
export function setApiLanguage(lang: Lang) {
  language = lang;
}

export class ApiError extends Error {
  status: number;
  body: Record<string, unknown>;
  constructor(status: number, body: Record<string, unknown>) {
    const detail = body?.detail;
    super(typeof detail === "string" ? detail : MESSAGES[language].httpError(status));
    this.status = status;
    this.body = body;
  }
}

let onUnauthorized: () => void = () => {};
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn;
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const { json, ...rest } = init;
  const res = await fetch(`/api${path}`, {
    credentials: "same-origin",
    ...rest,
    headers: {
      "Accept-Language": language,
      ...(json !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(rest.headers ?? {}),
    },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  if (!res.ok) {
    if (res.status === 401 && path !== "/auth/login") onUnauthorized();
    throw new ApiError(res.status, body);
  }
  return body as T;
}

export const get = <T,>(path: string) => api<T>(path);
export const post = <T,>(path: string, json: unknown = {}) => api<T>(path, { method: "POST", json });
export const put = <T,>(path: string, json: unknown = {}) => api<T>(path, { method: "PUT", json });
