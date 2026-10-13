"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { cn, short } from "@/lib/utils";
import { getAccountId, getToken, getUser, setAccountId, setToken, setUser } from "@/lib/api";
import { Logo } from "@/components/logo";
import {
  ShieldCheck,
  Boxes,
  FileText,
  Key,
  Cpu,
  Webhook,
  ScrollText,
  LayoutDashboard,
  LogOut,
} from "lucide-react";

const NAV = [
  { href: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "products", label: "Products", icon: Boxes },
  { href: "policies", label: "Policies", icon: FileText },
  { href: "licenses", label: "Licenses", icon: Key },
  { href: "machines", label: "Machines", icon: Cpu },
  { href: "webhooks", label: "Webhooks", icon: Webhook },
  { href: "tokens", label: "Tokens", icon: ShieldCheck },
  { href: "events", label: "Event Log", icon: ScrollText },
];

export function Shell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);
  const [accountId, setAcc] = useState<string | null>(null);

  useEffect(() => {
    const t = getToken();
    const a = getAccountId();
    if (!t || !a) {
      router.replace("/login");
      return;
    }
    setAcc(a);
    setReady(true);
  }, [router]);

  if (!ready) return null;
  const aid = accountId!;
  const logout = () => {
    setToken(null);
    setAccountId(null);
    setUser(null);
    router.replace("/login");
  };
  const user = getUser();
  const initials = (user?.full_name || user?.email || "?")
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join("");

  const active = (href: string) =>
    pathname === `/app/${aid}/${href}` || pathname?.startsWith(`/app/${aid}/${href}/`);

  const navLinks = (className?: string) =>
    NAV.map(({ href, label, icon: Icon }) => (
      <Link
        key={href}
        href={`/app/${aid}/${href}`}
        className={cn(
          "flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors",
          active(href)
            ? "bg-orange-500/10 font-medium text-orange-400"
            : "text-zinc-400 hover:bg-white/5 hover:text-zinc-100",
          className,
        )}
      >
        <Icon className="h-4 w-4 shrink-0" />
        {label}
      </Link>
    ));

  return (
    <div className="flex min-h-screen">
      {/* ── Sidebar (desktop) ─────────────────────────────────────────── */}
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-white/5 bg-zinc-950 md:flex">
        <div className="border-b border-white/5 px-4 py-5">
          <Link href="/" className="flex items-center gap-2.5">
            <Logo className="h-7 w-7" />
            <span className="font-semibold tracking-tight text-zinc-100">license-server</span>
          </Link>
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-white/5 bg-white/5 px-2.5 py-1.5">
            <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">org</span>
            <code className="truncate font-mono text-xs text-zinc-300" title={aid}>
              {short(aid, 12)}
            </code>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto p-3">{navLinks()}</nav>
        <div className="border-t border-white/5 p-3">
          <div className="flex items-center gap-2.5 rounded-lg px-2 py-2">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-orange-500/15 text-xs font-semibold text-orange-400">
              {initials}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm text-zinc-200">
                {user?.full_name || user?.email || "Account admin"}
              </span>
              {user?.full_name && (
                <span className="block truncate text-xs text-zinc-500" title={user.email}>
                  {user.email}
                </span>
              )}
            </span>
            <button
              onClick={logout}
              title="Sign out"
              className="rounded-md p-1.5 text-zinc-500 transition-colors hover:bg-white/5 hover:text-zinc-200"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Mobile top bar ────────────────────────────────────────────── */}
      <div className="fixed inset-x-0 top-0 z-30 border-b border-white/5 bg-zinc-950 md:hidden">
        <div className="flex items-center gap-2 px-4 py-2.5">
          <Logo className="h-6 w-6" />
          <span className="text-sm font-semibold text-zinc-100">license-server</span>
          <button
            onClick={logout}
            className="ml-auto rounded-md p-1.5 text-zinc-400 hover:bg-white/5 hover:text-zinc-200"
            title="Sign out"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-2">{navLinks("whitespace-nowrap")}</nav>
      </div>
      {/* Spacer so fixed mobile bar doesn't cover content */}
      <div className="h-[104px] shrink-0 md:hidden" />

      {/* ── Main ──────────────────────────────────────────────────────── */}
      <main className="min-w-0 flex-1 overflow-auto">
        <div className="mx-auto max-w-6xl p-6 md:p-8">{children}</div>
      </main>
    </div>
  );
}
