"use client";

import { use } from "react";
import { api, type Machine } from "@/lib/api";
import { useApi, State } from "@/components/use-api";
import { Card, CardContent, Badge, stateTone } from "@/components/ui";
import { fmtDate, short } from "@/lib/utils";

export default function MachinesPage({
  params,
}: {
  params: Promise<{ accountId: string }>;
}) {
  const { accountId } = use(params);
  const { data, error, loading } = useApi(
    () => api.listMachines(accountId),
    [accountId],
  );
  const rows: Machine[] = data?.data ?? [];
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">Machines</h1>
      <Card>
        <CardContent className="pt-6">
          <State loading={loading} error={error} empty={rows.length === 0}>
            <table className="w-full text-sm">
              <thead className="text-left text-muted-foreground">
                <tr>
                  <th className="py-2">Fingerprint</th><th>Name</th><th>Platform</th>
                  <th>State</th><th>Next heartbeat</th><th>License</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((m) => (
                  <tr key={m.id}>
                    <td className="py-2 font-mono text-xs">{m.fingerprint}</td>
                    <td>{m.name ?? "—"}</td>
                    <td>{m.platform ?? "—"}</td>
                    <td><Badge tone={stateTone(m.state)}>{m.state}</Badge></td>
                    <td className="text-muted-foreground">{fmtDate(m.next_heartbeat)}</td>
                    <td className="font-mono text-xs">{short(m.license_id)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </State>
        </CardContent>
      </Card>
    </div>
  );
}
