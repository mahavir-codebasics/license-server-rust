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

/** Compact relative time for timestamps: 'just now', '5m ago', '3h ago', '2d ago'. */
export function timeAgo(s?: string | null): string {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  const secs = Math.floor((Date.now() - d.getTime()) / 1000);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

/** Days until an RFC3339 timestamp; negative if past. Returns null when absent/invalid. */
export function daysUntil(s?: string | null): number | null {
  if (!s) return null;
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  return Math.ceil((d.getTime() - Date.now()) / 86_400_000);
}
