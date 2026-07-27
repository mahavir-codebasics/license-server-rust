"use client";

import { use } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/components/use-api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui";
import { Boxes, FileText, Key, Cpu } from "lucide-react";

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

  const stats = [
    { label: "Products", value: products.data?.data.length ?? 0, icon: Boxes },
    { label: "Policies", value: policies.data?.data.length ?? 0, icon: FileText },
    { label: "Licenses", value: licenses.data?.data.length ?? 0, icon: Key },
    { label: "Machines", value: machines.data?.data.length ?? 0, icon: Cpu },
  ];

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Dashboard</h1>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {stats.map(({ label, value, icon: Icon }) => (
          <Card key={label}>
            <CardContent className="pt-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">{label}</p>
                  <p className="text-3xl font-semibold mt-1">{value}</p>
                </div>
                <Icon className="h-8 w-8 text-muted-foreground/40" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Recent licenses</CardTitle>
        </CardHeader>
        <CardContent>
          {licenses.loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (licenses.data?.data.length ?? 0) === 0 ? (
            <p className="text-sm text-muted-foreground">No licenses yet.</p>
          ) : (
            <ul className="divide-y divide-border">
              {licenses.data?.data.slice(0, 5).map((l) => (
                <li key={l.id} className="py-2 flex items-center justify-between text-sm">
                  <code className="font-mono text-xs">{l.id.slice(0, 12)}…</code>
                  <span className="text-muted-foreground">{l.state}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
