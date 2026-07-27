"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { cn, short } from "@/lib/utils";
import { getAccountId, getToken, setAccountId, setToken } from "@/lib/api";
import { ShieldCheck, Boxes, FileText, Key, Cpu, Webhook, ScrollText, LayoutDashboard, LogOut, ChevronDown } from "lucide-react";

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
    router.replace("/login");
  };

  const active = (href: string) =>
    pathname === `/app/${aid}/${href}` || pathname?.startsWith(`/app/${aid}/${href}/`);

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="w-60 shrink-0 border-r border-border bg-white flex flex-col">
        <div className="px-4 py-5 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="h-7 w-7 rounded-md bg-primary text-primary-foreground flex items-center justify-center text-xs font-bold">
              LS
            </div>
            <span className="font-semibold">license-server</span>
          </div>
          <div className="mt-3 flex items-center gap-1 text-xs text-muted-foreground">
            <span>org:</span>
            <code className="font-mono">{short(aid, 10)}</code>
          </div>
        </div>
        <nav className="flex-1 p-2 space-y-0.5">
          {NAV.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={`/app/${aid}/${href}`}
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-2 text-sm",
                active(href)
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:bg-muted hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          ))}
        </nav>
        <button
          onClick={logout}
          className="m-2 flex items-center gap-2 rounded-md px-3 py-2 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </button>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-6xl p-8">{children}</div>
      </main>
    </div>
  );
}
