import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { setApiLanguage } from "./api";
import { MESSAGES, type Lang, type Messages } from "./messages";

const toDate = (iso: string) => new Date(iso + (iso.endsWith("Z") ? "" : "Z"));

export interface I18n {
  lang: Lang;
  setLang: (lang: Lang) => void;
  m: Messages;
  fmt: (n: number) => string;
  ago: (iso: string | null | undefined) => string;
  shortDate: (iso: string | null | undefined) => string;
  dateTime: (iso: string) => string;
}

function build(lang: Lang, setLang: (lang: Lang) => void): I18n {
  const m = MESSAGES[lang];
  return {
    lang,
    setLang,
    m,
    fmt: (n) => Math.round(n).toLocaleString(m.locale),
    ago: (iso) => {
      if (!iso) return m.ago.never;
      const s = (Date.now() - toDate(iso).getTime()) / 1000;
      if (s < 60) return m.ago.now;
      if (s < 3600) return m.ago.min(Math.round(s / 60));
      if (s < 86400) return m.ago.hours(Math.round(s / 3600));
      return m.ago.days(Math.round(s / 86400));
    },
    shortDate: (iso) => (iso ? toDate(iso).toLocaleDateString(m.locale, { day: "2-digit", month: "short" }) : "—"),
    dateTime: (iso) => toDate(iso).toLocaleString(m.locale),
  };
}

const I18nContext = createContext<I18n>(build("fr", () => {}));

export function I18nProvider({ children }: { children: ReactNode }) {
  // Global setting (Configuration > Language), read from /auth/me by App and updated on save.
  const [lang, setLangState] = useState<Lang>("fr");
  setApiLanguage(lang);

  const setLang = useCallback((next: Lang) => setLangState(next === "en" ? "en" : "fr"), []);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const value = useMemo(() => build(lang, setLang), [lang, setLang]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export const useI18n = () => useContext(I18nContext);
