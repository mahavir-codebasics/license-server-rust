import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Tailwind-aware className combiner. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format an RFC3339 timestamp for display; empty string -> '—'. */
export function fmtDate(s?: string | null): string {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Truncate a long id/key for display, with a tooltip title. */
export function short(s: string | null | undefined, n = 12): string {
  if (!s) return "—";
  return s.length <= n ? s : `${s.slice(0, n)}…`;
}
