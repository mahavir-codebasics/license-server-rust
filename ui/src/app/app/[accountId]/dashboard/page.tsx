"use client";

import { use } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { useApi } from "@/components/use-api";
import { Card, CardContent, CardHeader, CardTitle, Badge, stateTone } from "@/components/ui";
import { cn, daysUntil, short, timeAgo } from "@/lib/utils";
import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  FileText,
  Key,
  Cpu,
  Plus,
  ScrollText,
  ShieldCheck,
  Webhook,
} from "lucide-react";

export default function DashboardPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const products = useApi(() => api.listProducts(accountId), [accountId]);
  const policies = useApi(() => api.listPolicies(accountId), [accountId]);
  const licenses = useApi(() => api.listLicenses(accountId), [accountId]);
  const machines = useApi(() => api.listMachines(accountId), [accountId]);
  const events = useApi(() => api.listEvents(accountId), [accountId]);

  const productMap = new Map((products.data?.data ?? []).map((p) => [p.id, p.name]));
  const allLicenses = licenses.data?.data ?? [];
  const activeLicenses = allLicenses.filter((l) => l.state === "active");

  const stats = [
    { label: "Products", value: products.data?.data.length ?? 0, icon: Boxes, href: "products", tint: "bg-sky-500/10 text-sky-600" },
    { label: "Policies", value: policies.data?.data.length ?? 0, icon: FileText, href: "policies", tint: "bg-violet-500/10 text-violet-600" },
    { label: "Licenses", value: allLicenses.length, icon: Key, href: "licenses", tint: "bg-orange-500/10 text-orange-600", sub: `${activeLicenses.length} active` },
    { label: "Machines", value: machines.data?.data.length ?? 0, icon: Cpu, href: "machines", tint: "bg-emerald-500/10 text-emerald-600" },
  ];

  const quickActions = [
    { label: "New product", href: "products", icon: Plus },
    { label: "Issue license", href: "licenses", icon: Key },
    { label: "Create token", href: "tokens", icon: ShieldCheck },
    { label: "Add webhook", href: "webhooks", icon: Webhook },
  ];

  const expiringSoon = allLicenses
    .filter((l) => {
      const days = daysUntil(l.expiry);
      return l.state === "active" && days !== null && days <= 30;
    })
    .sort((a, b) => (a.expiry! < b.expiry! ? -1 : 1))
    .slice(0, 5);

  const isEmpty =
    !products.loading &&
    (products.data?.data.length ?? 0) === 0 &&
    (licenses.data?.data.length ?? 0) === 0;

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Everything happening across your licenses, at a glance.
        </p>
      </div>

      {/* Empty state for brand-new accounts */}
      {isEmpty && (
        <Card className="mb-8 border-dashed">
          <CardContent className="flex flex-col items-center py-12 text-center">
            <div className="mb-4 rounded-xl bg-orange-500/10 p-3 text-orange-600">
              <Boxes className="h-7 w-7" />
            </div>
            <h2 className="text-lg font-semibold">Create your first product</h2>
            <p className="mt-1 max-w-sm text-sm text-muted-foreground">
              Products group your policies and licenses. Add one, define a policy,
              then start issuing keys.
            </p>
            <Link
              href={`/app/${accountId}/products`}
              className="mt-5 inline-flex h-9 items-center gap-1.5 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            >
              <Plus className="h-4 w-4" />
              New product
            </Link>
          </CardContent>
        </Card>
      )}

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.map(({ label, value, icon: Icon, href, tint, sub }) => (
          <Link key={label} href={`/app/${accountId}/${href}`} className="group">
            <Card className="transition-all group-hover:border-orange-500/40 group-hover:shadow-md">
              <CardContent className="p-5">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">{label}</p>
                    <p className="mt-1 text-3xl font-semibold tabular-nums tracking-tight">{value}</p>
                    {sub && <p className="mt-1 text-xs text-muted-foreground">{sub}</p>}
                  </div>
                  <span className={cn("rounded-lg p-2.5", tint)}>
                    <Icon className="h-5 w-5" />
                  </span>
                </div>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>

      {/* Quick actions */}
      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {quickActions.map(({ label, href, icon: Icon }) => (
          <Link
            key={label}
            href={`/app/${accountId}/${href}`}
            className="flex items-center gap-2.5 rounded-lg border border-border bg-background px-4 py-3 text-sm font-medium text-muted-foreground shadow-sm transition-colors hover:border-orange-500/40 hover:text-foreground"
          >
            <Icon className="h-4 w-4 text-orange-600" />
            {label}
          </Link>
        ))}
      </div>

      {/* Licenses + events */}
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-base">Recent licenses</CardTitle>
            <Link
              href={`/app/${accountId}/licenses`}
              className="flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              View all
              <ArrowRight className="h-3 w-3" />
            </Link>
          </CardHeader>
          <CardContent className="pt-0">
            {licenses.loading ? (
              <p className="py-6 text-sm text-muted-foreground">Loading…</p>
            ) : allLicenses.length === 0 ? (
              <p className="py-6 text-sm text-muted-foreground">No licenses yet.</p>
            ) : (
              <ul className="divide-y divide-border">
                {allLicenses.slice(0, 5).map((l) => (
                  <li key={l.id} className="flex items-center justify-between gap-3 py-2.5">
                    <div className="min-w-0">
                      <code className="font-mono text-xs">{short(l.id, 14)}</code>
                      <p className="truncate text-xs text-muted-foreground">
                        {productMap.get(l.product_id) ?? short(l.product_id, 10)}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2.5">
                      <span className="hidden text-xs text-muted-foreground sm:inline">{timeAgo(l.created_at)}</span>
                      <Badge tone={stateTone(l.state)}>{l.state}</Badge>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <CardTitle className="text-base">Recent events</CardTitle>
            <Link
              href={`/app/${accountId}/events`}
              className="flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              View all
              <ArrowRight className="h-3 w-3" />
            </Link>
          </CardHeader>
          <CardContent className="pt-0">
            {events.loading ? (
              <p className="py-6 text-sm text-muted-foreground">Loading…</p>
            ) : (events.data?.data.length ?? 0) === 0 ? (
              <p className="py-6 text-sm text-muted-foreground">No events yet.</p>
            ) : (
              <ul className="divide-y divide-border">
                {events.data?.data.slice(0, 5).map((e) => (
                  <li key={e.id} className="flex items-center justify-between gap-3 py-2.5">
                    <div className="flex min-w-0 items-center gap-2.5">
                      <ScrollText className="h-3.5 w-3.5 shrink-0 text-muted-foreground/60" />
                      <code className="truncate font-mono text-xs">{e.event_type}</code>
                    </div>
                    <div className="flex shrink-0 items-center gap-2.5">
                      <span className="hidden text-xs text-muted-foreground sm:inline">{timeAgo(e.created_at)}</span>
                      <Badge tone={e.severity === "error" ? "red" : e.severity === "warn" ? "amber" : "gray"}>
                        {e.severity}
                      </Badge>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Expiring soon */}
      {expiringSoon.length > 0 && (
        <Card className="mt-4 border-amber-200 bg-amber-50/50">
          <CardHeader className="flex-row items-center gap-2 space-y-0">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            <CardTitle className="text-base">Expiring within 30 days</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <ul className="divide-y divide-amber-200/70">
              {expiringSoon.map((l) => {
                const days = daysUntil(l.expiry)!;
                return (
                  <li key={l.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                    <div className="flex min-w-0 items-center gap-3">
                      <code className="font-mono text-xs">{short(l.id, 14)}</code>
                      <span className="hidden truncate text-xs text-muted-foreground sm:inline">
                        {productMap.get(l.product_id) ?? short(l.product_id, 10)}
                      </span>
                    </div>
                    <span className={cn("shrink-0 text-xs font-medium", days <= 7 ? "text-rose-600" : "text-amber-700")}>
                      {days <= 0 ? "expired" : days === 1 ? "1 day left" : `${days} days left`}
                    </span>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
